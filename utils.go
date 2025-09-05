//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

func CheckOriginAllowed(remoteIP net.IP) bool {
	if len(Opts.AllowedSubnets) == 0 {
		return true
	}

	for _, ipNet := range Opts.AllowedSubnets {
		if ipNet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func DialUpstreamControl(sport int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			if Opts.Protocol == "tcp" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCTNT, 2): %w", syscallErr)
					return
				}
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1): %w", syscallErr)
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, SO_REUSEADDR, 1): %w", syscallErr)
				return
			}

			if sport == 0 {
				ipBindAddressNoPort := 24
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, IPPROTO_IP, %d): %w", Opts.Mark, syscallErr)
					return
				}
			}

			if Opts.Mark != 0 {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Opts.Mark)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %w", Opts.Mark, syscallErr)
					return
				}
			}

			if network == "tcp6" || network == "udp6" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IPV6_ONLY, 0): %w", syscallErr)
					return
				}
			}
		})

		if err != nil {
			return err
		}
		return syscallErr
	}
}

// executeCommand 执行系统命令并返回错误
func executeCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command '%s %v' failed: %w, output: %s", name, args, err, string(output))
	}
	return nil
}

// setupRoutingRules 设置透明代理所需的路由规则
func setupRoutingRules() error {
	Opts.Logger.Info("setting up routing rules for transparent proxy")
	
	// IPv4 路由规则（忽略错误，因为规则可能已经存在）
	if err := executeCommand("ip", "rule", "add", "from", "127.0.0.1/8", "iif", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to add IPv4 rule (may already exist)", "error", err)
	}
	
	if err := executeCommand("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to add IPv4 route (may already exist)", "error", err)
	}
	
	// IPv6 路由规则（忽略错误，因为规则可能已经存在）
	if err := executeCommand("ip", "-6", "rule", "add", "from", "::1/128", "iif", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to add IPv6 rule (may already exist)", "error", err)
	}
	
	if err := executeCommand("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to add IPv6 route (may already exist)", "error", err)
	}
	
	Opts.Logger.Info("routing rules set up successfully")
	return nil
}

// cleanupRoutingRules 清理透明代理的路由规则
func cleanupRoutingRules() {
	Opts.Logger.Info("cleaning up routing rules")
	
	// 清理IPv4路由规则（忽略错误，因为规则可能已经不存在）
	if err := executeCommand("ip", "rule", "del", "from", "127.0.0.1/8", "iif", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to remove IPv4 rule (may not exist)", "error", err)
	}
	
	if err := executeCommand("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to remove IPv4 route (may not exist)", "error", err)
	}
	
	// 清理IPv6路由规则（忽略错误，因为规则可能已经不存在）
	if err := executeCommand("ip", "-6", "rule", "del", "from", "::1/128", "iif", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to remove IPv6 rule (may not exist)", "error", err)
	}
	
	if err := executeCommand("ip", "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "123"); err != nil {
		Opts.Logger.Debug("failed to remove IPv6 route (may not exist)", "error", err)
	}
	
	Opts.Logger.Info("routing rules cleanup completed")
}

// checkPrivileges 检查程序是否有足够的权限执行ip命令
func checkPrivileges() error {
	// 检查是否为root用户
	if os.Geteuid() == 0 {
		return nil
	}
	
	// 如果不是root，尝试执行一个简单的ip命令来测试权限
	if err := executeCommand("ip", "rule", "list"); err != nil {
		return fmt.Errorf("insufficient privileges to execute ip commands. Please run as root or with CAP_NET_ADMIN capability: %w", err)
	}
	
	return nil
}
