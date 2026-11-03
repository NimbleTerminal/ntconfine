// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

//go:build !darwin && !linux && !windows

package ntconfine

import (
	"io"
	"os"
	"os/exec"
)

// Available reports whether OS sandbox enforcement is available on this platform.
func Available() bool { return false }

// Probe reports that OS sandbox enforcement is unavailable on this platform.
func Probe() Support {
	return Support{
		Available: false,
		Mechanism: MechanismNone,
		Detail:    "OS sandbox enforcement is not available on this platform",
	}
}

// DefaultLibPaths returns nil on unsupported platforms.
func DefaultLibPaths() []string { return nil }

// DefaultExecPaths returns nil on unsupported platforms.
func DefaultExecPaths() []string { return nil }

func verifyBinaryPlatform(string, os.FileInfo) error { return nil }

// Command is not available on this platform.
func Command(HelperConfig) (*exec.Cmd, Support, error) { return nil, Support{}, ErrUnavailable }

// StartHelper is not available on this platform.
func StartHelper(HelperConfig) (*Helper, error) { return nil, ErrUnavailable }

// InheritableFD is not available on this platform.
func (*Helper) InheritableFD() (int, error) { return 0, ErrUnavailable }

// KillHelper is a no-op on this platform.
func KillHelper(int) {}

func killHelperProcess(*os.Process) {}

// RunStage is not available on this platform.
func RunStage([]string) error { return ErrUnavailable }

// RunStagePolicy is not available on this platform.
func RunStagePolicy(Policy, string, []string) error { return ErrUnavailable }

// WorkerConn returns nil on unsupported platforms.
func WorkerConn() io.ReadWriteCloser { return nil }
