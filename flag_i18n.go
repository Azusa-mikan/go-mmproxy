//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Azusa-mikan/go-mmproxy/i18n"
)

// updateFlagUsage 更新flag的使用说明为国际化版本
func updateFlagUsage() {
	// 更新各个flag的使用说明
	flag.Lookup("p").Usage = i18n.T("flag.protocol.description")
	flag.Lookup("l").Usage = i18n.T("flag.listen.description")
	flag.Lookup("4").Usage = i18n.T("flag.target4.description")
	flag.Lookup("6").Usage = i18n.T("flag.target6.description")
	flag.Lookup("mark").Usage = i18n.T("flag.mark.description")
	flag.Lookup("v").Usage = i18n.T("flag.verbose.description")
	flag.Lookup("allowed-subnets").Usage = i18n.T("flag.allowed_subnets.description")
	flag.Lookup("listeners").Usage = i18n.T("flag.listeners.description")
	flag.Lookup("close-after").Usage = i18n.T("flag.close_after.description")

	// 自定义Usage函数
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
}
