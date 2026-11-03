// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

// Package ntconfine launches, restricts, supervises, and terminates OS-confined
// worker subprocesses on Linux (Landlock + seccomp-bpf + rlimits) and macOS
// (sandbox-exec SBPL), failing closed when OS enforcement is required and
// unavailable.
package ntconfine

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

const (
	// StageArg is the CLI flag passed to ntconfine-stage before the spec token or "fd:<N>".
	StageArg = confine.StageArg

	// SpecVersion is the wire version of StageSpec.
	SpecVersion = confine.SpecVersion

	// DefaultStageBinary is the default standalone stage executable name.
	DefaultStageBinary = "ntconfine-stage"
)

// ErrUnavailable means this machine cannot enforce the requested OS sandbox policy.
var ErrUnavailable = confine.ErrUnavailable

// Mechanism names the OS sandbox mechanism used to confine a worker process.
type Mechanism = confine.Mechanism

const (
	MechanismNone        = confine.MechanismNone
	MechanismLandlock    = confine.MechanismLandlock
	MechanismSandboxExec = confine.MechanismSandboxExec
)

// Support describes the OS sandbox enforcement capability of the current host
// or of a running Helper.
type Support = confine.Support

// Policy defines the OS confinement for a worker subprocess.
// The zero value is closed: no paths are readable, writable, or executable,
// network and terminal access are denied, and OS enforcement is required.
type Policy = confine.Policy

// StageSpec is the language-neutral launch specification passed to ntconfine-stage.
type StageSpec = confine.StageSpec

// EncodeStageSpec serializes spec as JSON and encodes it as raw URL-safe base64.
var EncodeStageSpec = confine.EncodeStageSpec

// DecodeStageSpec decodes a raw URL-safe base64 StageSpec token.
var DecodeStageSpec = confine.DecodeStageSpec

// DefaultPolicy returns the standard worker policy for helperBin reading from
// readPaths (such as a private staging directory and any resolved input file).
// WritePaths is nil and AllowUnsandboxed is false.
func DefaultPolicy(helperBin string, readPaths ...string) Policy {
	reads := slices.Clone(DefaultLibPaths())
	for _, p := range readPaths {
		if p != "" {
			reads = append(reads, p)
		}
	}
	execs := slices.Clone(DefaultExecPaths())
	if helperBin != "" {
		execs = append(execs, helperBin)
	}
	return Policy{
		ReadPaths:        reads,
		WritePaths:       nil,
		ExecPaths:        execs,
		AllowUnsandboxed: false,
	}
}

// HelperConfig configures how StartHelper or Command launches a confined worker.
type HelperConfig struct {
	Policy     Policy
	WorkerPath string     // path to worker executable
	WorkerArgs []string   // arguments passed to worker
	StagePath  string     // stage binary on Linux; defaults to ResolveSibling(DefaultStageBinary)
	StageArgs  []string   // optional prefix args before StageArg
	ExtraFiles []*os.File // optional additional inherited descriptors (starting after fd 3 in StartHelper or at fd 3 in Command)
}

// Helper is a running worker subprocess supervised by the host.
type Helper struct {
	Conn      io.ReadWriteCloser
	cmd       *exec.Cmd
	stderr    *confine.BoundedBuffer
	cleanup   func()
	closeOnce sync.Once
	closeErr  error
	enforced  bool
	support   Support
}

// PID returns the worker process ID.
func (h *Helper) PID() int {
	if h == nil || h.cmd == nil || h.cmd.Process == nil {
		return 0
	}
	return h.cmd.Process.Pid
}

// Enforced reports whether OS sandbox confinement was applied to this worker.
func (h *Helper) Enforced() bool {
	if h == nil {
		return false
	}
	return h.enforced
}

// Support reports the OS sandbox mechanism applied to this worker.
func (h *Helper) Support() Support {
	if h == nil {
		return Support{Mechanism: MechanismNone}
	}
	return h.support
}

// Stderr returns bounded, control-stripped standard error output captured from
// the stage or worker process.
func (h *Helper) Stderr() string {
	if h == nil || h.stderr == nil {
		return ""
	}
	return h.stderr.String()
}

// Close closes the worker connection and terminates and reaps the worker process.
func (h *Helper) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		if h.Conn != nil {
			h.closeErr = h.Conn.Close()
		}
		if h.cmd != nil && h.cmd.Process != nil {
			killHelperProcess(h.cmd.Process)
			_ = h.cmd.Wait()
		}
		if h.cleanup != nil {
			h.cleanup()
		}
	})
	return h.closeErr
}

// ResolveSibling resolves a binary by bare name in the same directory as the
// current executable (after resolving symlinks on os.Executable()), and verifies
// its ownership and permissions with VerifyBinary. It never searches $PATH.
func ResolveSibling(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("ntconfine: invalid sibling binary name %q", name)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	candidate := filepath.Join(filepath.Dir(exe), name)
	return VerifyBinary(candidate)
}

// VerifyBinary resolves symlinks on path and checks that it is a regular
// executable file with safe ownership and permissions (not group- or
// world-writable, not setuid/setgid, owned by the current effective UID or root,
// and in a non-world-writable or sticky directory on Unix).
func VerifyBinary(path string) (string, error) {
	if err := confine.ValidateCleanAbsPath(path); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("ntconfine: resolve binary %s: %w", path, err)
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("ntconfine: stat binary %s: %w", resolved, err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("ntconfine: binary %s is not a regular file", resolved)
	}
	if err := verifyBinaryPlatform(resolved, st); err != nil {
		return "", err
	}
	return resolved, nil
}
