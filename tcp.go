//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/Azusa-mikan/go-mmproxy/i18n"
)

func tcpCopyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

func tcpHandleConnection(conn net.Conn, logger *slog.Logger) {
	defer conn.Close()
	logger = logger.With(slog.String("remoteAddr", conn.RemoteAddr().String()),
		slog.String("localAddr", conn.LocalAddr().String()))

	if !CheckOriginAllowed(conn.RemoteAddr().(*net.TCPAddr).IP) {
		logger.Debug(i18n.T("log.tcp.connection_origin_not_allowed"), slog.Bool("dropConnection", true))
		return
	}

	if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.new_connection"))
	}

	buffer := GetBuffer()
	defer func() {
		if buffer != nil {
			PutBuffer(buffer)
		}
	}()

	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug(i18n.T("log.tcp.proxy_header_read_failed"), "error", err, slog.Bool("dropConnection", true))
		return
	}

	saddr, _, restBytes, err := PROXYReadRemoteAddr(buffer[:n], TCP)
	if err != nil {
		logger.Debug(i18n.T("log.tcp.proxy_header_parse_failed"), "error", err, slog.Bool("dropConnection", true))
		return
	}

	targetAddr := Opts.TargetAddr6
	if saddr == nil {
		if netip.MustParseAddrPort(conn.RemoteAddr().String()).Addr().Is4() {
			targetAddr = Opts.TargetAddr4
		}
	} else if netip.MustParseAddrPort(saddr.String()).Addr().Is4() {
		targetAddr = Opts.TargetAddr4
	}

	// 检查IPv6目标地址是否已配置
	if !targetAddr.Addr().Is4() && Opts.TargetAddr6Str == "" {
		logger.Error(i18n.T("error.target6_addr.not_configured"))
		return
	}

	clientAddr := "UNKNOWN"
	if saddr != nil {
		clientAddr = saddr.String()
	}
	logger = logger.With(slog.String("clientAddr", clientAddr), slog.String("targetAddr", targetAddr.String()))
	if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.proxy_header_parsed"))
	}

	dialer := net.Dialer{LocalAddr: saddr}
	if saddr != nil {
		dialer.Control = DialUpstreamControl(saddr.(*net.TCPAddr).Port)
	}
	upstreamConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		logger.Debug(i18n.T("log.tcp.upstream_connection_failed"), "error", err, slog.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.upstream_connection_success"))
	}

	if nodeDelayErr := conn.(*net.TCPConn).SetNoDelay(true); nodeDelayErr != nil {
		logger.Debug(i18n.T("log.tcp.nodelay_downstream_failed"), "error", nodeDelayErr, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.nodelay_downstream_success"))
	}

	if nodeDelayErr := upstreamConn.(*net.TCPConn).SetNoDelay(true); nodeDelayErr != nil {
		logger.Debug(i18n.T("log.tcp.nodelay_upstream_failed"), "error", nodeDelayErr, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.nodelay_upstream_success"))
	}

	for len(restBytes) > 0 {
		n, writeErr := upstreamConn.Write(restBytes)
		if writeErr != nil {
			logger.Debug(i18n.T("log.tcp.upstream_write_failed"),
				"error", writeErr, slog.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	PutBuffer(buffer)
	buffer = nil

	outErr := make(chan error, 2)
	go tcpCopyData(upstreamConn, conn, outErr)
	go tcpCopyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		logger.Debug(i18n.T("log.tcp.connection_broken"), "error", err, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.tcp.connection_closing"))
	}
}

func TCPListen(listenConfig *net.ListenConfig, logger *slog.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.Listen(ctx, "tcp", Opts.ListenAddr.String())
	if err != nil {
		logger.Error(i18n.T("log.tcp.bind_failed"), "error", err)
		errors <- err
		return
	}

	logger.Info(i18n.T("log.tcp.listening"))

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error(i18n.T("log.tcp.accept_failed"), "error", err)
			errors <- err
			return
		}

		go tcpHandleConnection(conn, logger)
	}
}
