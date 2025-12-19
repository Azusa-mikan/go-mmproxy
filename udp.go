//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Azusa-mikan/go-mmproxy/i18n"
)

type udpConnection struct {
	lastActivity   *int64
	clientAddr     *net.UDPAddr
	downstreamAddr *net.UDPAddr
	upstream       *net.UDPConn
	logger         *slog.Logger
}

func udpCloseAfterInactivity(conn *udpConnection, socketClosures chan<- string) {
	for {
		lastActivity := atomic.LoadInt64(conn.lastActivity)
		<-time.After(Opts.UDPCloseAfter)
		if atomic.LoadInt64(conn.lastActivity) == lastActivity {
			break
		}
	}
	conn.upstream.Close()
	if conn.clientAddr != nil {
		socketClosures <- conn.clientAddr.String()
	} else {
		socketClosures <- ""
	}
}

func udpCopyFromUpstream(downstream net.PacketConn, conn *udpConnection) {
	rawConn, err := conn.upstream.SyscallConn()
	if err != nil {
		conn.logger.Error(i18n.T("log.udp.upstream_raw_connection_failed"), "error", err)
		return
	}

	var syscallErr error

	err = rawConn.Read(func(fd uintptr) bool {
		buf := GetBuffer()
		defer PutBuffer(buf)

		for {
			n, _, serr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			if errors.Is(serr, syscall.EWOULDBLOCK) {
				return false
			}
			if serr != nil {
				syscallErr = serr
				return true
			}
			if n == 0 {
				return true
			}

			atomic.AddInt64(conn.lastActivity, 1)

			if _, serr := downstream.WriteTo(buf[:n], conn.downstreamAddr); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}
	if err != nil {
		conn.logger.Debug(i18n.T("log.udp.upstream_read_failed"), "error", err)
	}
}

func udpGetSocketFromMap(downstream net.PacketConn, downstreamAddr, saddr net.Addr, logger *slog.Logger,
	connMap map[string]*udpConnection, socketClosures chan<- string) (*udpConnection, error) {
	connKey := ""
	if saddr != nil {
		connKey = saddr.String()
	}
	if conn := connMap[connKey]; conn != nil {
		atomic.AddInt64(conn.lastActivity, 1)
		return conn, nil
	}

	targetAddr := Opts.TargetAddr6
	if udpAddr, ok := downstreamAddr.(*net.UDPAddr); ok && udpAddr.IP.To4() != nil {
		targetAddr = Opts.TargetAddr4
	}

	// 检查IPv6目标地址是否已配置
	if !targetAddr.Addr().Is4() && Opts.TargetAddr6Str == "" {
		logger.Error(i18n.T("error.target6_addr.not_configured"))
		return nil, fmt.Errorf("IPv6 target address not configured")
	}

	logger = logger.With(slog.String("downstreamAddr", downstreamAddr.String()), slog.String("targetAddr", targetAddr.String()))
	dialer := net.Dialer{LocalAddr: saddr}
	if saddr != nil {
		logger = logger.With(slog.String("clientAddr", saddr.String()))
		dialer.Control = DialUpstreamControl(saddr.(*net.UDPAddr).Port)
	}

	if Opts.Verbose > 1 {
		logger.Debug(i18n.T("log.udp.new_connection"))
	}

	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		logger.Debug(i18n.T("log.udp.upstream_connect_failed"), "error", err)
		return nil, err
	}

	udpConn := &udpConnection{upstream: conn.(*net.UDPConn),
		logger:         logger,
		lastActivity:   new(int64),
		downstreamAddr: downstreamAddr.(*net.UDPAddr)}
	if saddr != nil {
		udpConn.clientAddr = saddr.(*net.UDPAddr)
	}

	go udpCopyFromUpstream(downstream, udpConn)
	go udpCloseAfterInactivity(udpConn, socketClosures)

	connMap[connKey] = udpConn
	return udpConn, nil
}

func UDPListen(listenConfig *net.ListenConfig, logger *slog.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.ListenPacket(ctx, "udp", Opts.ListenAddr.String())
	if err != nil {
		logger.Error(i18n.T("log.udp.bind_failed"), "error", err)
		errors <- err
		return
	}

	logger.Info(i18n.T("log.udp.listening"))

	socketClosures := make(chan string, 1024)
	connectionMap := make(map[string]*udpConnection)

	buffer := GetBuffer()
	defer PutBuffer(buffer)

	for {
		n, remoteAddr, err := ln.ReadFrom(buffer)
		if err != nil {
			logger.Error(i18n.T("log.udp.read_failed"), "error", err)
			continue
		}

		if !CheckOriginAllowed(remoteAddr.(*net.UDPAddr).IP) {
			logger.Debug(i18n.T("log.udp.packet_origin_not_allowed"), slog.String("remoteAddr", remoteAddr.String()))
			continue
		}

		saddr, _, restBytes, err := PROXYReadRemoteAddr(buffer[:n], UDP)
		if err != nil {
			logger.Debug(i18n.T("log.udp.proxy_header_parse_failed"), "error", err, slog.String("remoteAddr", remoteAddr.String()))
			continue
		}

		for {
			doneClosing := false
			select {
			case mapKey := <-socketClosures:
				delete(connectionMap, mapKey)
			default:
				doneClosing = true
			}
			if doneClosing {
				break
			}
		}

		conn, err := udpGetSocketFromMap(ln, remoteAddr, saddr, logger, connectionMap, socketClosures)
		if err != nil {
			continue
		}

		_, err = conn.upstream.Write(restBytes)
		if err != nil {
			conn.logger.Error(i18n.T("log.udp.upstream_write_failed"), "error", err)
		}
	}
}
