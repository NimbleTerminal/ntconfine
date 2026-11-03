// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build darwin || linux

package confine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"
)

const stageWaitDelay = 2 * time.Second

// Process is a running worker subprocess launched via an external
// ntconfine-stage binary.
type Process struct {
	Conn      io.ReadWriteCloser
	cmd       *exec.Cmd
	stderr    *BoundedBuffer
	closeOnce sync.Once
	closeErr  error
}

// PID returns the process ID of the launched worker/stage.
func (p *Process) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Stderr returns bounded, control-stripped standard error output captured from
// the stage or worker process.
func (p *Process) Stderr() string {
	if p == nil || p.stderr == nil {
		return ""
	}
	return p.stderr.String()
}

// Close closes the communication socket and terminates and reaps the worker
// process group.
func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		if p.Conn != nil {
			p.closeErr = p.Conn.Close()
		}
		if p.cmd != nil && p.cmd.Process != nil {
			if pid := p.cmd.Process.Pid; pid > 0 {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
			_ = p.cmd.Process.Kill()
			_ = p.cmd.Wait()
		}
	})
	return p.closeErr
}

// StartStage launches an external ntconfine-stage executable (at stagePath,
// with optional prefix stageArgs before StageArg) using the stage launch contract:
//   - fd 3 in the worker is one end of a CLOEXEC-hardened socketpair (the other
//     end is returned as Process.Conn in non-blocking mode for deadline support)
//   - extraFiles (if any) are inherited at fd 4..3+len(extraFiles)
//   - the encoded StageSpec is passed over an anonymous pipe at fd:<4+len(extraFiles)>
func StartStage(stagePath string, stageArgs []string, spec StageSpec, extraFiles ...*os.File) (*Process, error) {
	if err := ValidateCleanAbsPath(stagePath); err != nil {
		return nil, err
	}
	if err := ValidateCleanAbsPath(spec.WorkerPath); err != nil {
		return nil, err
	}
	if !slices.Contains(spec.Policy.ExecPaths, spec.WorkerPath) {
		spec.Policy.ExecPaths = append(slices.Clone(spec.Policy.ExecPaths), spec.WorkerPath)
	}
	if err := spec.Policy.Validate(); err != nil {
		return nil, err
	}
	specB64, err := EncodeStageSpec(spec)
	if err != nil {
		return nil, err
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	fds, err := socketpairCloexec()
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	ours := os.NewFile(uintptr(fds[0]), "confine-stage-host")
	theirs := os.NewFile(uintptr(fds[1]), "confine-stage-child")

	specFD := 4 + len(extraFiles)
	args := make([]string, 0, len(stageArgs)+2)
	args = append(args, stageArgs...)
	args = append(args, StageArg, fmt.Sprintf("fd:%d", specFD))

	cmd := exec.Command(stagePath, args...)
	stderr := NewBoundedBuffer(MaxStderrBytes)
	cmd.Stderr = stderr
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = stageWaitDelay

	files := make([]*os.File, 0, 2+len(extraFiles))
	files = append(files, theirs)
	files = append(files, extraFiles...)
	files = append(files, pr)
	cmd.ExtraFiles = files

	if err := cmd.Start(); err != nil {
		_ = theirs.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = ours.Close()
		return nil, errors.Join(err)
	}
	_ = theirs.Close()
	_ = pr.Close()

	if _, err := io.WriteString(pw, specB64); err != nil {
		_ = pw.Close()
		_ = ours.Close()
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		return nil, err
	}
	if err := pw.Close(); err != nil {
		_ = ours.Close()
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		return nil, err
	}
	return &Process{
		Conn:   ours,
		cmd:    cmd,
		stderr: stderr,
	}, nil
}
