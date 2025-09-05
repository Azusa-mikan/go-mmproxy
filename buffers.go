//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"math"
	"sync"
)

var buffers sync.Pool

func init() {
	buffers.New = func() any { return &[]byte{} }
}

func GetBuffer() []byte {
	buf := buffers.Get().(*[]byte)
	if cap(*buf) < math.MaxUint16 {
		*buf = make([]byte, math.MaxUint16)
	} else {
		*buf = (*buf)[:math.MaxUint16]
	}
	return *buf
}

func PutBuffer(buf []byte) {
	buffers.Put(&buf)
}
