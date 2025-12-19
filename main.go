//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Azusa-mikan/go-mmproxy/i18n"
)

type options struct {
	Protocol           string
	ListenAddrStr      string
	TargetAddr4Str     string
	TargetAddr6Str     string
	ListenAddr         netip.AddrPort
	TargetAddr4        netip.AddrPort
	TargetAddr6        netip.AddrPort
	Mark               int
	Verbose            int
	allowedSubnetsPath string
	AllowedSubnets     []*net.IPNet
	Listeners          int
	Logger             *slog.Logger
	udpCloseAfter      int
	UDPCloseAfter      time.Duration
}

var Opts options

func init() {
	flag.StringVar(&Opts.Protocol, "p", "tcp", "Protocol that will be proxied: tcp, udp, all (both tcp and udp) (default: tcp)")
	flag.StringVar(&Opts.ListenAddrStr, "l", "", "Address the proxy listens on")
	flag.StringVar(&Opts.TargetAddr4Str, "4", "", "Address to which IPv4 traffic will be forwarded to")
	flag.StringVar(&Opts.TargetAddr6Str, "6", "", "Address to which IPv6 traffic will be forwarded to")
	flag.IntVar(&Opts.Mark, "mark", 0, "The mark that will be set on outbound packets (default: 0)")
	flag.IntVar(&Opts.Verbose, "v", 0, `Verbosity level (default: 0):
0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&Opts.allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&Opts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+) (default: 1)")
	flag.IntVar(&Opts.udpCloseAfter, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up (default: 60)")
}

func listen(listenerNum int, errors chan<- error) {
	logger := Opts.Logger.With(slog.Int("listenerNum", listenerNum),
		slog.String("protocol", Opts.Protocol), slog.String("listenAdr", Opts.ListenAddr.String()))

	// 配置监听器，支持多个监听器时启用 SO_REUSEPORT
	listenConfig := net.ListenConfig{}
	if Opts.Listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn(i18n.T("log.so_reuseport_failed"))
				}
			})
		}
	}

	// 根据协议参数启动相应的监听器
	switch Opts.Protocol {
	case "tcp":
		// 仅启动 TCP 监听器
		TCPListen(&listenConfig, logger, errors)
	case "udp":
		// 仅启动 UDP 监听器
		UDPListen(&listenConfig, logger, errors)
	case "all":
		// 同时启动 TCP 和 UDP 监听器
		// 创建独立的错误通道，避免阻塞
		tcpErrors := make(chan error, 1)
		udpErrors := make(chan error, 1)

		// 启动 TCP 监听器（在独立的 goroutine 中）
		go func() {
			tcpLogger := logger.With(slog.String("actualProtocol", "tcp"))
			tcpLogger.Info(i18n.T("log.tcp_listener_starting"))
			defer func() {
				if r := recover(); r != nil {
					tcpLogger.Error(i18n.T("log.tcp_listener_panicked"), "panic", r)
					tcpErrors <- fmt.Errorf("TCP listener panicked: %v", r)
				}
			}()
			TCPListen(&listenConfig, tcpLogger, tcpErrors)
		}()

		// 启动 UDP 监听器（在独立的 goroutine 中）
		go func() {
			udpLogger := logger.With(slog.String("actualProtocol", "udp"))
			udpLogger.Info(i18n.T("log.udp_listener_starting"))
			defer func() {
				if r := recover(); r != nil {
					udpLogger.Error(i18n.T("log.udp_listener_panicked"), "panic", r)
					udpErrors <- fmt.Errorf("UDP listener panicked: %v", r)
				}
			}()
			UDPListen(&listenConfig, udpLogger, udpErrors)
		}()

		// 监控两个协议的错误状态
		// 如果任一协议启动失败，记录错误但不退出程序
		tcpFailed := false
		udpFailed := false

		for {
			select {
			case tcpErr := <-tcpErrors:
				if !tcpFailed {
					tcpFailed = true
					logger.Warn(i18n.T("log.tcp_listener_failed"), "error", tcpErr)
					// 如果 UDP 也已经失败，则向主错误通道发送错误
					if udpFailed {
						errors <- fmt.Errorf("%s", i18n.T("log.both_listeners_failed"))
						return
					}
				}
			case udpErr := <-udpErrors:
				if !udpFailed {
					udpFailed = true
					logger.Warn(i18n.T("log.udp_listener_failed"), "error", udpErr)
					// 如果 TCP 也已经失败，则向主错误通道发送错误
					if tcpFailed {
						errors <- fmt.Errorf("%s", i18n.T("log.both_listeners_failed"))
						return
					}
				}
			}
		}
	}
}

func loadAllowedSubnets() error {
	file, err := os.Open(Opts.allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return err
		}
		Opts.AllowedSubnets = append(Opts.AllowedSubnets, ipNet)
		Opts.Logger.Info(i18n.T("log.allowed_subnet"), slog.String("subnet", ipNet.String()))
	}

	return nil
}

func main() {
	// 初始化国际化系统（自动检测系统语言）
	if err := i18n.Init(""); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize i18n: %v\n", err)
		os.Exit(1)
	}

	// 更新命令行参数的国际化描述
	updateFlagUsage()

	// 如果没有提供任何参数，显示帮助信息
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	flag.Parse()
	lvl := slog.LevelInfo
	if Opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}
	Opts.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	if Opts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			Opts.Logger.Error(i18n.T("error.allowed_subnets.load_failed"), "path", Opts.allowedSubnetsPath, "error", err)
		}
	}

	// 验证协议参数：支持 tcp、udp 或 all（同时支持两种协议）
	if Opts.Protocol != "tcp" && Opts.Protocol != "udp" && Opts.Protocol != "all" {
		Opts.Logger.Error(i18n.T("error.protocol.invalid"), slog.String("protocol", Opts.Protocol))
		os.Exit(1)
	}

	if Opts.Mark < 0 {
		Opts.Logger.Error(i18n.T("error.mark.invalid"), slog.Int("mark", Opts.Mark))
		os.Exit(1)
	}

	if Opts.Verbose < 0 {
		Opts.Logger.Error(i18n.T("error.verbose.invalid"), slog.Int("verbose", Opts.Verbose))
		os.Exit(1)
	}

	if Opts.Listeners < 1 {
		Opts.Logger.Error(i18n.T("error.listeners.invalid"))
		os.Exit(1)
	}

	var err error
	if Opts.ListenAddr, err = netip.ParseAddrPort(Opts.ListenAddrStr); err != nil {
		Opts.Logger.Error(i18n.T("error.listen_addr.malformed"), "error", err)
		os.Exit(1)
	}

	if Opts.TargetAddr4, err = netip.ParseAddrPort(Opts.TargetAddr4Str); err != nil {
		Opts.Logger.Error(i18n.T("error.target4_addr.malformed"), "error", err)
		os.Exit(1)
	}
	if !Opts.TargetAddr4.Addr().Is4() {
		Opts.Logger.Error(i18n.T("error.target4_addr.not_ipv4"))
		os.Exit(1)
	}

	// IPv6目标地址是可选的
	if Opts.TargetAddr6Str != "" {
		if Opts.TargetAddr6, err = netip.ParseAddrPort(Opts.TargetAddr6Str); err != nil {
			Opts.Logger.Error(i18n.T("error.target6_addr.malformed"), "error", err)
			os.Exit(1)
		}
		if !Opts.TargetAddr6.Addr().Is6() {
			Opts.Logger.Error(i18n.T("error.target6_addr.not_ipv6"))
			os.Exit(1)
		}
	}

	if Opts.udpCloseAfter < 0 {
		Opts.Logger.Error(i18n.T("error.close_after.invalid"), slog.Int("close-after", Opts.udpCloseAfter))
		os.Exit(1)
	}
	Opts.UDPCloseAfter = time.Duration(Opts.udpCloseAfter) * time.Second

	// 检查权限
	if err := checkPrivileges(); err != nil {
		Opts.Logger.Error(i18n.T("error.privilege_check.failed"), "error", err)
		os.Exit(1)
	}

	if err := setupRoutingRules(); err != nil {
		Opts.Logger.Error(i18n.T("error.routing_rules.setup_failed"), "error", err)
		if isPermissionError(err) {
			Opts.Logger.Error(i18n.T("error.routing_rules.permission"))
		}
		os.Exit(1)
	}

	// 设置信号处理，确保程序退出时清理路由规则
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		Opts.Logger.Info(i18n.T("log.shutdown_signal"))
		cleanupRoutingRules()
		os.Exit(0)
	}()

	// 确保程序正常退出时也清理路由规则
	defer cleanupRoutingRules()

	listenErrors := make(chan error, Opts.Listeners)
	for i := 0; i < Opts.Listeners; i++ {
		go listen(i, listenErrors)
	}
	for i := 0; i < Opts.Listeners; i++ {
		<-listenErrors
	}
}
