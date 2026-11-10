// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

const sandboxExec = "/usr/bin/sandbox-exec"

var availableOnce = sync.OnceValue(func() bool { return applies(sandboxExec) })

// Available reports whether /usr/bin/sandbox-exec can apply a policy on this host.
// Inside an outer sandbox it cannot apply a nested policy, so it is probed once.
func Available() bool { return availableOnce() }

func applies(tool string) bool {
	return exec.Command(tool, "-p", "(version 1)(allow default)", "/usr/bin/true").Run() == nil
}

func socketpairCloexec() ([2]int, error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	return fds, err
}

// Probe reports the macOS sandbox-exec capability of the current host.
//
// Note on macOS resource limits: unlike the Linux stage (which sets RLIMIT_AS,
// RLIMIT_NOFILE, RLIMIT_NPROC, and RLIMIT_CORE before execve), macOS
// /usr/bin/sandbox-exec does not set rlimits and setrlimit(RLIMIT_AS) is not
// enforced by the Darwin kernel; hosts rely on per-request context timeouts and
// explicit pixel/byte caps on macOS.
func Probe() Support {
	if Available() {
		return Support{
			Available:  true,
			Mechanism:  MechanismSandboxExec,
			Deprecated: true,
			Detail:     "macOS /usr/bin/sandbox-exec (deprecated by Apple; denies network, mach-lookup, /dev/tty, /Users, /private/etc, and unlisted paths)",
		}
	}
	return Support{
		Available:  false,
		Mechanism:  MechanismNone,
		Deprecated: true,
		Detail:     "macOS /usr/bin/sandbox-exec is unavailable or nested inside an outer sandbox",
	}
}

// DefaultLibPaths returns the default library and font search directories for a
// confined worker on macOS. Both Apple Silicon (/opt/homebrew) and Intel (/usr/local)
// are narrowed to lib, Cellar, and opt so service data (/opt/homebrew/var) and
// configuration files (/opt/homebrew/etc) remain unreadable.
func DefaultLibPaths() []string {
	return []string{
		"/opt/homebrew/lib",
		"/opt/homebrew/Cellar",
		"/opt/homebrew/opt",
		"/usr/local/lib",
		"/usr/local/Cellar",
		"/usr/local/opt",
		"/usr/lib",
		"/System/Library",
		"/Library/Fonts",
	}
}

// DefaultExecPaths returns the default system loader executables on macOS.
// dyld is covered by system.sb, so none are required beyond the worker binary.
func DefaultExecPaths() []string { return nil }

func q(s string) string { return strconv.Quote(s) }

func sbplPathFilter(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return fmt.Sprintf("(subpath %s)", q(p))
	}
	return fmt.Sprintf("(literal %s)", q(p))
}

func appendAncestorLiterals(dst []string, path string) []string {
	if path == "" {
		return dst
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	dir := filepath.Dir(filepath.Clean(path))
	for {
		lit := fmt.Sprintf("(literal %s)", q(dir))
		if !slices.Contains(dst, lit) {
			dst = append(dst, lit)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return dst
}

// HelperPolicy renders the macOS sandbox-exec SBPL profile for pol.
func HelperPolicy(pol Policy) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("(version 1)")
	w("(deny default)")
	w("(import \"dyld-support.sb\")")
	w("(allow syscall*)")
	w("(allow system-mac-syscall)")
	w("(allow mach-bootstrap)")
	w("(deny mach-lookup)")
	w("(deny mach-register)")
	w("(deny ipc-posix-shm*)")
	w("(deny file-write* (subpath \"/cores\"))")
	w("(deny file-read* file-test-existence (subpath \"/private/etc\") (subpath \"/etc\") (subpath \"/Users\") (subpath \"/private/var/root\"))")

	var execLiterals []string
	metaLiterals := []string{
		"(literal \"/tmp\")",
		"(literal \"/var\")",
		"(literal \"/private\")",
	}
	for _, exe := range pol.ExecPaths {
		if exe == "" {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		lit := fmt.Sprintf("(literal %s)", q(exe))
		if !slices.Contains(execLiterals, lit) {
			execLiterals = append(execLiterals, lit)
		}
		metaLiterals = appendAncestorLiterals(metaLiterals, exe)
	}
	if len(execLiterals) > 0 {
		w("(allow process-exec %s)", strings.Join(execLiterals, " "))
	}

	w("(allow signal (target self))")
	w("(allow sysctl-read)")

	readFilters := slices.Clone(execLiterals)
	for _, rp := range pol.ReadPaths {
		if rp == "" {
			continue
		}
		f := sbplPathFilter(rp)
		if !slices.Contains(readFilters, f) {
			readFilters = append(readFilters, f)
		}
		metaLiterals = appendAncestorLiterals(metaLiterals, rp)
	}
	if len(readFilters) > 0 {
		w("(allow file-read* file-test-existence file-map-executable %s)", strings.Join(readFilters, " "))
	}

	var writeFilters []string
	for _, wp := range pol.WritePaths {
		if wp == "" {
			continue
		}
		f := sbplPathFilter(wp)
		if !slices.Contains(writeFilters, f) {
			writeFilters = append(writeFilters, f)
		}
		metaLiterals = appendAncestorLiterals(metaLiterals, wp)
	}
	if len(writeFilters) > 0 {
		w("(allow file-read* file-write* file-test-existence %s)", strings.Join(writeFilters, " "))
	}
	if len(metaLiterals) > 0 {
		w("(allow file-read-metadata file-test-existence %s)", strings.Join(metaLiterals, " "))
	}

	w("(allow file-read* file-write* file-test-existence (literal \"/dev/null\"))")
	w("(allow file-read* file-test-existence (literal \"/dev/urandom\") (literal \"/dev/random\"))")
	// Explicit denies last, so they hold even if a caller lists /dev or a
	// parent directory in ReadPaths or WritePaths.
	w("(deny file-read* file-write* (literal \"/dev/tty\"))")
	w("(deny network*)")
	return b.String()
}

var sharedProfileDir = sync.OnceValues(func() (string, error) {
	return os.MkdirTemp("", "ntconfine-sbpl-*")
})

func writeProfileFile(sbpl string, ephemeral bool) (string, func(), error) {
	if ephemeral {
		f, err := os.CreateTemp("", "ntconfine-*.sb")
		if err != nil {
			return "", nil, err
		}
		name := f.Name()
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			_ = os.Remove(name)
			return "", nil, err
		}
		if _, err := f.WriteString(sbpl); err != nil {
			_ = f.Close()
			_ = os.Remove(name)
			return "", nil, err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(name)
			return "", nil, err
		}
		return name, func() { _ = os.Remove(name) }, nil
	}
	dir, err := sharedProfileDir()
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(sbpl))
	name := filepath.Join(dir, hex.EncodeToString(sum[:16])+".sb")
	if _, err := os.Stat(name); os.IsNotExist(err) {
		tmp := name + ".tmp"
		if err := os.WriteFile(tmp, []byte(sbpl), 0o600); err != nil {
			return "", nil, err
		}
		if err := os.Rename(tmp, name); err != nil {
			_ = os.Remove(tmp)
			return "", nil, err
		}
	}
	return name, func() {}, nil
}

func helperCommand(cfg HelperConfig, workerPath string, ephemeral bool) (*exec.Cmd, func(), error) {
	pol := cfg.Policy
	if !slices.Contains(pol.ExecPaths, workerPath) {
		pol.ExecPaths = append(slices.Clone(pol.ExecPaths), workerPath)
	}
	profilePath, cleanup, err := writeProfileFile(HelperPolicy(pol), ephemeral)
	if err != nil {
		return nil, nil, err
	}
	args := make([]string, 0, 3+len(cfg.WorkerArgs))
	args = append(args, "-f", profilePath, workerPath)
	args = append(args, cfg.WorkerArgs...)
	cmd := exec.Command(sandboxExec, args...)
	if len(cfg.ExtraFiles) > 0 {
		cmd.ExtraFiles = slices.Clone(cfg.ExtraFiles)
	}
	return cmd, cleanup, nil
}

// RunStage parses the encoded stage specification from args (either via an
// inherited pipe descriptor "fd:<N>" or an inline base64 token) and replaces
// the current process with /usr/bin/sandbox-exec enforcing the policy on
// WorkerPath (enabling cross-language hosts such as Rust to invoke
// ntconfine-stage identically on macOS and Linux). It returns only on failure.
func RunStage(args []string) error {
	var token string
	switch {
	case len(args) == 2 && args[0] == StageArg:
		token = args[1]
	case len(args) == 1 && strings.HasPrefix(args[0], StageArg+"="):
		token = strings.TrimPrefix(args[0], StageArg+"=")
	case len(args) == 1 && args[0] != "" && !strings.HasPrefix(args[0], "-"):
		token = args[0]
	default:
		return fmt.Errorf("ntconfine: usage: %s <spec>", StageArg)
	}
	if fromFD, ok, err := confine.ReadSpecFromFD(token); ok {
		if err != nil {
			return err
		}
		token = fromFD
	}
	spec, err := DecodeStageSpec(token)
	if err != nil {
		return err
	}
	return RunStagePolicy(spec.Policy, spec.WorkerPath, spec.WorkerArgs)
}

func stageProfilePath(sbpl string) (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("ntconfine-sbpl-%d", os.Geteuid()))
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if st, statErr := os.Lstat(dir); statErr == nil && st.IsDir() && st.Mode().Perm() == 0o700 {
			if raw, ok := st.Sys().(*syscall.Stat_t); ok && int(raw.Uid) == os.Geteuid() {
				sum := sha256.Sum256([]byte(sbpl))
				name := filepath.Join(dir, hex.EncodeToString(sum[:16])+".sb")
				if _, err := os.Stat(name); os.IsNotExist(err) {
					if tmpFile, err := os.CreateTemp(dir, "sbpl-*.tmp"); err == nil {
						tmpName := tmpFile.Name()
						_ = tmpFile.Chmod(0o600)
						_, werr := tmpFile.WriteString(sbpl)
						cerr := tmpFile.Close()
						if werr == nil && cerr == nil && os.Rename(tmpName, name) == nil {
							return name, nil
						}
						_ = os.Remove(tmpName)
					}
				} else if err == nil {
					return name, nil
				}
			}
		}
	}
	profilePath, _, err := writeProfileFile(sbpl, false)
	return profilePath, err
}

// RunStagePolicy validates pol and workerPath and replaces the current process
// with /usr/bin/sandbox-exec enforcing pol via a 0600 "-f" SBPL profile file
// (so policy paths never appear in argv / ps).
func RunStagePolicy(pol Policy, workerPath string, workerArgs []string) error {
	if err := pol.Validate(); err != nil {
		return err
	}
	resolvedWorker, err := VerifyBinary(workerPath)
	if err != nil {
		return err
	}
	if !Available() {
		if !pol.AllowUnsandboxed {
			return ErrUnavailable
		}
		argv := make([]string, 0, 1+len(workerArgs))
		argv = append(argv, resolvedWorker)
		argv = append(argv, workerArgs...)
		return syscall.Exec(resolvedWorker, argv, []string{})
	}
	if !slices.Contains(pol.ExecPaths, resolvedWorker) {
		pol.ExecPaths = append(slices.Clone(pol.ExecPaths), resolvedWorker)
	}
	profilePath, err := stageProfilePath(HelperPolicy(pol))
	if err != nil {
		return err
	}
	argv := make([]string, 0, 4+len(workerArgs))
	argv = append(argv, sandboxExec, "-f", profilePath, resolvedWorker)
	argv = append(argv, workerArgs...)
	return syscall.Exec(sandboxExec, argv, []string{})
}
