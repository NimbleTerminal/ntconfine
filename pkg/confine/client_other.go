// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package confine

import (
	"io"
	"os"
)

// Process is a running worker subprocess launched via an external
// ntconfine-stage binary.
type Process struct {
	Conn io.ReadWriteCloser
}

// PID returns 0 on unsupported platforms.
func (*Process) PID() int { return 0 }

// Stderr returns empty string on unsupported platforms.
func (*Process) Stderr() string { return "" }

// Close is a no-op on unsupported platforms.
func (*Process) Close() error { return nil }

// StartStage is not supported on non-Unix platforms.
func StartStage(string, []string, StageSpec, ...*os.File) (*Process, error) {
	return nil, ErrUnavailable
}
