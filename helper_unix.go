// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

//go:build darwin || linux

package ntconfine

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

const helperWaitDelay = 2 * time.Second

func verifyBinaryPlatform(resolved string, st os.FileInfo) error {
	mode := st.Mode()
	if mode.Perm()&0o111 == 0 {
		return fmt.Errorf("ntconfine: binary %s is not executable (mode %04o)", resolved, mode.Perm())
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("ntconfine: binary %s is group- or world-writable (mode %04o)", resolved, mode.Perm())
	}
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("ntconfine: binary %s has setuid/setgid bit set (mode %v)", resolved, mode)
	}
	if raw, ok := st.Sys().(*syscall.Stat_t); ok {
		euid := os.Geteuid()
		if euid >= 0 && raw.Uid != uint32(euid) && raw.Uid != 0 {
			return fmt.Errorf("ntconfine: binary %s has untrusted owner uid %d (want %d or 0)", resolved, raw.Uid, euid)
		}
	}
	dir := filepath.Dir(resolved)
	dirSt, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ntconfine: stat parent directory %s: %w", dir, err)
	}
	dirMode := dirSt.Mode()
	if dirMode.Perm()&0o002 != 0 && dirMode&os.ModeSticky == 0 {
		return fmt.Errorf("ntconfine: parent directory %s is world-writable without sticky bit (mode %04o)", dir, dirMode.Perm())
	}
	return nil
}

// Command constructs the confined (or unsandboxed fallback when
// Policy.AllowUnsandboxed is true and OS enforcement is unavailable) *exec.Cmd
// for a worker without starting it or attaching a socketpair. It sets an empty
// environment, a new session with no controlling terminal, and a bounded stderr buffer.
func Command(cfg HelperConfig) (*exec.Cmd, Support, error) {
	cmd, sup, _, _, err := commandWithMode(cfg, false)
	return cmd, sup, err
}

func commandWithMode(cfg HelperConfig, ephemeral bool) (*exec.Cmd, Support, *confine.BoundedBuffer, func(), error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, Support{}, nil, nil, err
	}
	workerPath, err := VerifyBinary(cfg.WorkerPath)
	if err != nil {
		return nil, Support{}, nil, nil, err
	}
	sup := Probe()
	enforced := sup.Available
	var (
		cmd     *exec.Cmd
		cleanup func()
	)
	if enforced {
		cmd, cleanup, err = helperCommand(cfg, workerPath, ephemeral)
		if err != nil {
			return nil, Support{}, nil, nil, err
		}
	} else {
		if !cfg.Policy.AllowUnsandboxed {
			return nil, Support{}, nil, nil, ErrUnavailable
		}
		sup = Support{
			Available: false,
			Mechanism: MechanismNone,
			Detail:    "OS sandbox enforcement unavailable; running unsandboxed (AllowUnsandboxed=true)",
		}
		cmd = exec.Command(workerPath, cfg.WorkerArgs...)
		if len(cfg.ExtraFiles) > 0 {
			cmd.ExtraFiles = slices.Clone(cfg.ExtraFiles)
		}
	}
	stderr := confine.NewBoundedBuffer(confine.MaxStderrBytes)
	cmd.Stderr = stderr
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = helperWaitDelay
	return cmd, sup, stderr, cleanup, nil
}

// StartHelper starts the worker process before the host locks itself down.
// On Unix, the worker receives its connection socket on fd 3 (followed by any
// cfg.ExtraFiles), an empty environment, a new session with no controlling
// terminal, bounded stderr capture, and OS confinement defined by cfg.Policy.
func StartHelper(cfg HelperConfig) (*Helper, error) {
	cmd, sup, stderr, cleanup, err := commandWithMode(cfg, true)
	if err != nil {
		return nil, err
	}
	enforced := sup.Available
	extraFiles := cmd.ExtraFiles
	callerCount := len(cfg.ExtraFiles)
	defer func() {
		// Close internal stage pipe fds attached after cfg.ExtraFiles.
		for i := callerCount; i < len(extraFiles); i++ {
			if f := extraFiles[i]; f != nil {
				_ = f.Close()
			}
		}
	}()

	fds, err := socketpairCloexec()
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	// Put the host's descriptor into non-blocking mode before wrapping with
	// os.NewFile so Go registers it with the runtime netpoller (enabling real
	// read/write deadlines and allowing Close to interrupt a blocked Read).
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	ours := os.NewFile(uintptr(fds[0]), "confine-helper")
	theirs := os.NewFile(uintptr(fds[1]), "confine-helper-child")
	defer func() { _ = theirs.Close() }()

	cmd.ExtraFiles = append([]*os.File{theirs}, extraFiles...)

	if err := cmd.Start(); err != nil {
		_ = ours.Close()
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	return &Helper{
		Conn:     ours,
		cmd:      cmd,
		stderr:   stderr,
		cleanup:  cleanup,
		enforced: enforced,
		support:  sup,
	}, nil
}

// InheritableFD duplicates the host's socket descriptor without O_CLOEXEC so it
// can survive a macOS main-process sandbox-exec re-exec. Because the returned
// descriptor lacks O_CLOEXEC, callers must invoke InheritableFD immediately
// before syscall.Exec without starting other child processes in between.
func (h *Helper) InheritableFD() (int, error) {
	if h == nil {
		return 0, ErrUnavailable
	}
	f, ok := h.Conn.(*os.File)
	if !ok || f == nil {
		return 0, ErrUnavailable
	}
	return syscall.Dup(int(f.Fd()))
}

func killHelperProcess(p *os.Process) {
	if p == nil || p.Pid <= 0 {
		return
	}
	// Setsid makes the helper process the leader of its own process group
	// (pgid == pid), so signaling -pid terminates any forked grandchildren too.
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}

// KillHelper terminates a worker process (and its process group) by PID.
func KillHelper(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// WorkerConn returns the worker side's connection to the host (fd 3 on Unix).
func WorkerConn() io.ReadWriteCloser {
	return os.NewFile(3, "socket")
}
