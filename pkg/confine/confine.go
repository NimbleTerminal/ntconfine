// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

// Package confine defines the language-neutral launch contract and policy
// specification for starting OS-confined worker processes via ntconfine-stage.
package confine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// StageArg is the CLI flag passed to ntconfine-stage before the spec token or "fd:<N>".
	StageArg = "--stage"

	// SpecVersion is the current wire version of StageSpec.
	SpecVersion = 1

	// MaxSpecBytes is the maximum encoded StageSpec size read from a stage pipe.
	MaxSpecBytes = 1 << 20

	// MaxStderrBytes is the maximum stderr output retained from a stage or worker process.
	MaxStderrBytes = 16 << 10
)

// ErrUnavailable means this machine cannot enforce the requested OS sandbox policy.
var ErrUnavailable = errors.New("ntconfine: OS sandbox enforcement is not available here")

// Mechanism names the OS sandbox mechanism used to confine a worker process.
type Mechanism string

const (
	MechanismNone        Mechanism = "none"
	MechanismLandlock    Mechanism = "landlock+seccomp"
	MechanismSandboxExec Mechanism = "sandbox-exec"
)

// Support describes the OS sandbox enforcement capability of the current host
// or of a running confined worker.
type Support struct {
	Available   bool
	Mechanism   Mechanism
	LandlockABI int    // 1..6 on Linux when Available; 0 elsewhere
	Deprecated  bool   // true on macOS: Apple deprecated sandbox-exec
	Detail      string // human-readable summary of enforcement and caveats
}

// Policy defines the OS confinement for a worker subprocess.
// The zero value is closed: no paths are readable, writable, or executable,
// network and terminal access are denied, and OS enforcement is required.
type Policy struct {
	ReadPaths        []string `json:"read_paths,omitempty"`
	WritePaths       []string `json:"write_paths,omitempty"`
	ExecPaths        []string `json:"exec_paths,omitempty"`
	AllowUnsandboxed bool     `json:"allow_unsandboxed,omitempty"`
	// Optional Linux stage rlimit caps (0 uses safe defaults: RLIMIT_CORE=0,
	// RLIMIT_NOFILE=1024, RLIMIT_AS=16 GiB, RLIMIT_NPROC=4096). Note that on
	// Linux RLIMIT_NPROC is enforced by the kernel against total tasks across
	// the real UID.
	MaxAddressSpace uint64 `json:"max_address_space,omitempty"`
	MaxOpenFiles    uint64 `json:"max_open_files,omitempty"`
	MaxProcesses    uint64 `json:"max_processes,omitempty"`
}

// ValidateCleanAbsPath checks that path is a non-empty, absolute, valid UTF-8
// filesystem path with no C0/C1 control characters or DEL.
func ValidateCleanAbsPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || !utf8.ValidString(path) {
		return fmt.Errorf("ntconfine: invalid path %q (must be absolute valid UTF-8)", path)
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("ntconfine: control character in path %q", path)
		}
	}
	return nil
}

// Validate checks that the policy is well-formed and not the closed zero value.
func (p Policy) Validate() error {
	if len(p.ExecPaths) == 0 {
		return errors.New("ntconfine: policy has no executable paths")
	}
	for _, list := range [][]string{p.ReadPaths, p.WritePaths, p.ExecPaths} {
		for _, path := range list {
			if err := ValidateCleanAbsPath(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// StageSpec is the language-neutral launch specification passed to ntconfine-stage
// over an inherited pipe descriptor ("fd:<N>").
type StageSpec struct {
	Version    int      `json:"version,omitempty"`
	Policy     Policy   `json:"policy"`
	WorkerPath string   `json:"worker_path"`
	WorkerArgs []string `json:"worker_args,omitempty"`
}

// EncodeStageSpec serializes spec as JSON and encodes it as raw URL-safe base64.
func EncodeStageSpec(spec StageSpec) (string, error) {
	if spec.Version == 0 {
		spec.Version = SpecVersion
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeStageSpec decodes a raw URL-safe base64 StageSpec token and validates
// its version (0 or SpecVersion).
func DecodeStageSpec(s string) (StageSpec, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return StageSpec{}, fmt.Errorf("ntconfine: invalid stage spec encoding: %w", err)
	}
	var spec StageSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return StageSpec{}, fmt.Errorf("ntconfine: invalid stage spec JSON: %w", err)
	}
	if spec.Version != 0 && spec.Version != SpecVersion {
		return StageSpec{}, fmt.Errorf("ntconfine: unsupported stage spec version %d (want %d)", spec.Version, SpecVersion)
	}
	if spec.Version == 0 {
		spec.Version = SpecVersion
	}
	return spec, nil
}

// ReadSpecFromFD reads an encoded StageSpec from an "fd:<N>" argument (where N >= 3)
// and closes the descriptor. If arg does not start with "fd:", ok is false.
func ReadSpecFromFD(arg string) (string, bool, error) {
	if !strings.HasPrefix(arg, "fd:") {
		return "", false, nil
	}
	fdNum, err := strconv.Atoi(strings.TrimPrefix(arg, "fd:"))
	if err != nil || fdNum < 3 {
		return "", true, fmt.Errorf("ntconfine: invalid stage spec fd %q", arg)
	}
	f := os.NewFile(uintptr(fdNum), "stage-spec")
	if f == nil {
		return "", true, fmt.Errorf("ntconfine: bad stage spec fd %d", fdNum)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxSpecBytes+1))
	if err != nil {
		return "", true, fmt.Errorf("ntconfine: read stage spec fd %d: %w", fdNum, err)
	}
	if len(raw) == 0 || len(raw) > MaxSpecBytes {
		return "", true, errors.New("ntconfine: stage spec size out of bounds")
	}
	return strings.TrimSpace(string(raw)), true, nil
}

// BoundedBuffer captures up to max bytes of stderr output and strips terminal
// control characters when read as a string.
type BoundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

// NewBoundedBuffer returns a BoundedBuffer capped at maxBytes.
func NewBoundedBuffer(maxBytes int) *BoundedBuffer {
	return &BoundedBuffer{max: maxBytes}
}

// Write appends up to the remaining capacity and always reports len(p) consumed.
func (b *BoundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	origLen := len(p)
	rem := b.max - b.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		_, _ = b.buf.Write(p)
	}
	return origLen, nil
}

// String returns the captured contents with C0/C1 controls and DEL stripped.
func (b *BoundedBuffer) String() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	raw := b.buf.String()
	b.mu.Unlock()
	var out strings.Builder
	out.Grow(len(raw))
	for _, r := range raw {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f)) {
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}
