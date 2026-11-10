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
	MaxStderrBytes = 64 << 10

	// MaxPolicyPaths is the maximum number of entries in each Policy path list.
	MaxPolicyPaths = 128

	// MaxPolicyPathBytes is the maximum total byte length of all Policy paths.
	MaxPolicyPathBytes = 32768
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
	LandlockABI int    // 3..10 on Linux when Available (capped at the highest ABI this package handles); 0 elsewhere
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
// filesystem path with no C0/C1 control characters or DEL, and that it is
// already in filepath.Clean form (no "." or ".." elements, repeated separators,
// or trailing separator).
func ValidateCleanAbsPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || !utf8.ValidString(path) {
		return fmt.Errorf("ntconfine: invalid path %q (must be absolute valid UTF-8)", path)
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("ntconfine: control character in path %q", path)
		}
	}
	// Forward slashes are accepted as written on Windows, where Clean rewrites them.
	if clean := filepath.Clean(path); clean != path && filepath.ToSlash(clean) != path {
		return fmt.Errorf("ntconfine: path %q is not clean (want %q)", path, clean)
	}
	return nil
}

// Validate checks that the policy is well-formed and not the closed zero value:
// ExecPaths is non-empty, each path list holds at most MaxPolicyPaths entries,
// all paths together are at most MaxPolicyPathBytes bytes, and every path
// passes ValidateCleanAbsPath.
func (p Policy) Validate() error {
	if len(p.ExecPaths) == 0 {
		return errors.New("ntconfine: policy has no executable paths")
	}
	total := 0
	for _, list := range [][]string{p.ReadPaths, p.WritePaths, p.ExecPaths} {
		if len(list) > MaxPolicyPaths {
			return fmt.Errorf("ntconfine: policy path list has %d entries (max %d)", len(list), MaxPolicyPaths)
		}
		for _, path := range list {
			total += len(path)
			if total > MaxPolicyPathBytes {
				return fmt.Errorf("ntconfine: policy paths exceed %d bytes in total", MaxPolicyPathBytes)
			}
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
	if base64.RawURLEncoding.EncodedLen(len(raw)) > MaxSpecBytes {
		return "", fmt.Errorf("ntconfine: encoded stage spec exceeds %d bytes", MaxSpecBytes)
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

// String returns the captured contents sanitized with SanitizeTerminalText.
func (b *BoundedBuffer) String() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	raw := b.buf.String()
	b.mu.Unlock()
	return SanitizeTerminalText(raw)
}

// SanitizeTerminalText makes untrusted process output safe to print on a
// terminal. It removes whole ANSI escape sequences (CSI, OSC, DCS, SOS, PM,
// APC, and two-byte ESC sequences), every remaining C0/C1 control character
// except newline and tab, DEL, Unicode bidirectional formatting controls, and
// invalid UTF-8, then trims surrounding whitespace.
func SanitizeTerminalText(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))
	rs := []rune(raw)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b && i+1 < len(rs):
			i = skipEscapeSequence(rs, i+1)
		case r == 0x9b: // C1 CSI
			i = skipCSI(rs, i+1)
		case r == 0x90 || r == 0x98 || r == 0x9d || r == 0x9e || r == 0x9f: // C1 DCS, SOS, OSC, PM, APC
			i = skipStringSequence(rs, i+1)
		case r == utf8.RuneError, isBidiControl(r):
		case r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f)):
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

// skipEscapeSequence consumes the sequence introduced by an ESC whose next
// rune is rs[i] and returns the index of its last rune.
func skipEscapeSequence(rs []rune, i int) int {
	switch rs[i] {
	case '[':
		return skipCSI(rs, i+1)
	case ']', 'P', 'X', '^', '_':
		return skipStringSequence(rs, i+1)
	}
	// nF sequences: intermediates 0x20..0x2f followed by one final byte.
	for i < len(rs) && rs[i] >= 0x20 && rs[i] <= 0x2f {
		i++
	}
	if i < len(rs) && rs[i] >= 0x30 && rs[i] <= 0x7e {
		return i
	}
	return i - 1
}

// skipCSI consumes CSI parameter and intermediate bytes starting at rs[i] and
// the final byte, returning the index of the last rune consumed.
func skipCSI(rs []rune, i int) int {
	for i < len(rs) && rs[i] >= 0x20 && rs[i] <= 0x3f {
		i++
	}
	if i < len(rs) && rs[i] >= 0x40 && rs[i] <= 0x7e {
		return i
	}
	return i - 1
}

// skipStringSequence consumes an OSC/DCS/SOS/PM/APC payload starting at rs[i]
// up to and including its BEL or ST terminator. An unterminated payload is
// dropped up to the end of its line so it cannot swallow later output.
func skipStringSequence(rs []rune, i int) int {
	for ; i < len(rs); i++ {
		switch {
		case rs[i] == 0x07 || rs[i] == 0x9c:
			return i
		case rs[i] == 0x1b && i+1 < len(rs) && rs[i+1] == '\\':
			return i + 1
		case rs[i] == '\n':
			return i - 1
		}
	}
	return i
}

// isBidiControl reports whether r is a Unicode bidirectional formatting
// control (marks, embeddings, overrides, and isolates).
func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}
