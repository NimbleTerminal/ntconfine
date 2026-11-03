// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

//go:build windows

package ntconfine

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

const helperWaitDelay = 2 * time.Second

// Available reports whether OS sandbox enforcement is available on Windows.
func Available() bool { return false }

// Probe reports that OS sandbox enforcement is not implemented on Windows.
func Probe() Support {
	return Support{
		Available: false,
		Mechanism: MechanismNone,
		Detail:    "OS sandbox enforcement is not implemented on Windows",
	}
}

// DefaultLibPaths returns nil on Windows.
func DefaultLibPaths() []string { return nil }

// DefaultExecPaths returns nil on Windows.
func DefaultExecPaths() []string { return nil }

func verifyBinaryPlatform(resolved string, st os.FileInfo) error {
	if st.Size() == 0 {
		return fmt.Errorf("ntconfine: binary %s is empty", resolved)
	}
	return nil
}

type pipeConn struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeConn) Close() error {
	errW := p.w.Close()
	errR := p.r.Close()
	if errW != nil {
		return errW
	}
	return errR
}

// Command constructs the unsandboxed fallback *exec.Cmd on Windows when
// Policy.AllowUnsandboxed is true, failing closed with ErrUnavailable otherwise.
func Command(cfg HelperConfig) (*exec.Cmd, Support, error) {
	cmd, sup, _, err := commandWindows(cfg)
	return cmd, sup, err
}

func commandWindows(cfg HelperConfig) (*exec.Cmd, Support, *confine.BoundedBuffer, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, Support{}, nil, err
	}
	workerPath, err := VerifyBinary(cfg.WorkerPath)
	if err != nil {
		return nil, Support{}, nil, err
	}
	if !cfg.Policy.AllowUnsandboxed {
		return nil, Support{}, nil, ErrUnavailable
	}
	cmd := exec.Command(workerPath, cfg.WorkerArgs...)
	var env []string
	for _, k := range []string{"SystemRoot", "SYSTEMROOT", "WINDIR", "PATH"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = env
	stderr := confine.NewBoundedBuffer(confine.MaxStderrBytes)
	cmd.Stderr = stderr
	cmd.WaitDelay = helperWaitDelay
	sup := Support{
		Available: false,
		Mechanism: MechanismNone,
		Detail:    "OS sandbox enforcement is not implemented on Windows; running unsandboxed (AllowUnsandboxed=true)",
	}
	return cmd, sup, stderr, nil
}

// StartHelper starts the worker process on Windows. Because OS sandbox
// enforcement is unavailable on Windows, StartHelper fails closed with
// ErrUnavailable unless cfg.Policy.AllowUnsandboxed is true.
func StartHelper(cfg HelperConfig) (*Helper, error) {
	cmd, sup, stderr, err := commandWindows(cfg)
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	return &Helper{
		Conn:     &pipeConn{r: stdout, w: stdin},
		cmd:      cmd,
		stderr:   stderr,
		enforced: false,
		support:  sup,
	}, nil
}

// InheritableFD is not supported on Windows.
func (*Helper) InheritableFD() (int, error) { return 0, ErrUnavailable }

func killHelperProcess(p *os.Process) {
	if p != nil {
		_ = p.Kill()
	}
}

// KillHelper terminates a worker process by PID.
func KillHelper(pid int) {
	if pid > 0 {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
}

// RunStage is not supported on Windows.
func RunStage([]string) error { return ErrUnavailable }

// RunStagePolicy is not supported on Windows.
func RunStagePolicy(Policy, string, []string) error { return ErrUnavailable }

// WorkerConn returns the worker side's connection to the host (stdin/stdout on Windows).
func WorkerConn() io.ReadWriteCloser {
	return &pipeConn{r: os.Stdin, w: os.Stdout}
}
