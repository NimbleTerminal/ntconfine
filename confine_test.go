// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

const (
	probeMarker   = "nt-helper-probe"
	stderrMarker  = "nt-helper-stderr"
	sleepMarker   = "nt-helper-sleep"
	extraFDMarker = "nt-helper-extrafd"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == StageArg {
		fmt.Println(RunStage(os.Args[1:])) // stage: never returns on success
		os.Exit(9)
	}
	if len(os.Args) >= 2 && os.Args[1] == stderrMarker {
		fmt.Fprint(os.Stderr, "worker-stderr\x1b[31m-line\n")
		conn := WorkerConn()
		_, _ = conn.Write([]byte("ready\n"))
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if len(os.Args) >= 2 && os.Args[1] == sleepMarker {
		_ = WorkerConn()
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if len(os.Args) >= 2 && os.Args[1] == extraFDMarker {
		conn := WorkerConn()
		extra := os.NewFile(4, "extra")
		data, err := io.ReadAll(extra)
		_ = extra.Close()
		if err != nil {
			_, _ = fmt.Fprintf(conn, "err:%v\n", err)
		} else {
			_, _ = fmt.Fprintf(conn, "extra:%s\n", strings.TrimSpace(string(data)))
		}
		_ = conn.Close()
		os.Exit(0)
	}
	if len(os.Args) >= 2 && strings.Contains(os.Args[1], probeMarker) {
		var singleFile, siblingFile string
		if len(os.Args) >= 4 {
			singleFile = os.Args[2]
			siblingFile = os.Args[3]
		}
		helperProbe(os.Args[1], singleFile, siblingFile)
	}
	os.Exit(m.Run())
}

// helperProbe runs inside the confined worker process: fd 3 (or stdin/stdout on
// Windows) is the host connection, argv[1] is the staging directory, and
// argv[2]/argv[3] are optional paths testing single-file read rules.
func helperProbe(tmp, singleFile, siblingFile string) {
	conn := WorkerConn()
	report := func(name string, err error) { _, _ = fmt.Fprintf(conn, "%s=%v\n", name, err == nil) }
	_, _ = fmt.Fprintf(conn, "env=%d\n", len(os.Environ()))
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 500*time.Millisecond)
	if c != nil {
		_ = c.Close()
	}
	report("network", err)
	_, err = os.ReadFile("/etc/passwd")
	report("passwd", err)
	_, err = os.ReadFile(filepath.Join(tmp, "clip"))
	report("readtemp", err)
	report("writetemp", os.WriteFile(filepath.Join(tmp, "new"), []byte("x"), 0o600))
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if f != nil {
		_ = f.Close()
	}
	report("tty", err)
	victim := tmp + "-victim"
	report("truncate", os.Truncate(victim, 0))
	report("chmod", os.Chmod(victim, 0o777))
	report("uring", platformProbe())
	if singleFile != "" {
		_, err = os.ReadFile(singleFile)
		report("singlefile", err)
		tf, terr := os.OpenFile(singleFile, os.O_RDONLY|os.O_TRUNC, 0)
		if tf != nil {
			_ = tf.Close()
		}
		report("opentrunc", terr)
		_, err = os.ReadFile(filepath.Join(tmp, "linked-clip"))
		report("linkedfile", err)
	}
	if siblingFile != "" {
		_, err = os.ReadFile(siblingFile)
		report("siblingfile", err)
		_, err = os.ReadDir(filepath.Dir(siblingFile))
		report("siblingdir", err)
	}
	_, _ = fmt.Fprintln(conn, "done")
	_ = conn.Close()
	os.Exit(0)
}

func runProbe(t *testing.T) map[string]string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp("", probeMarker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "clip"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp+"-victim", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmp + "-victim") })

	outsideDir, err := os.MkdirTemp("", "nt-helper-outside-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })
	if outsideDir, err = filepath.EvalSymlinks(outsideDir); err != nil {
		t.Fatal(err)
	}
	singleFile := filepath.Join(outsideDir, "allowed.dat")
	siblingFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(singleFile, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(siblingFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(singleFile, filepath.Join(tmp, "linked-clip")); err != nil {
		t.Fatal(err)
	}

	pol := DefaultPolicy(exe, tmp, singleFile)
	h, err := StartHelper(HelperConfig{
		Policy:     pol,
		WorkerPath: exe,
		WorkerArgs: []string{tmp, singleFile, siblingFile},
		StagePath:  exe,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	if !h.Enforced() {
		t.Fatal("expected helper to report Enforced() == true")
	}
	if f, ok := h.Conn.(*os.File); ok {
		_ = f.SetDeadline(time.Now().Add(10 * time.Second))
	}
	got := map[string]string{}
	r := bufio.NewReader(h.Conn)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF || err != nil || strings.TrimSpace(line) == "done" {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		got[k] = v
	}
	return got
}

func TestHelperIsConfined(t *testing.T) {
	if !Available() {
		if os.Getenv("NTCONFINE_REQUIRE_SANDBOX") == "1" {
			t.Fatal("OS enforcement unavailable here (NTCONFINE_REQUIRE_SANDBOX=1)")
		}
		t.Skip("OS enforcement unavailable here")
	}
	got := runProbe(t)
	want := map[string]string{
		"env":         "0",
		"network":     "false",
		"passwd":      "false",
		"readtemp":    "true",
		"writetemp":   "false",
		"tty":         "false",
		"truncate":    "false",
		"chmod":       "false",
		"uring":       "false",
		"singlefile":  "true",
		"opentrunc":   "false",
		"linkedfile":  "true",
		"siblingfile": "false",
		"siblingdir":  "false",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestStartStageContractAndExtraFiles(t *testing.T) {
	if !Available() {
		t.Skip("OS enforcement unavailable here")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	if _, err := io.WriteString(pw, "inherited-fd4-ok\n"); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

	// Exercise the pkg/confine.StartStage launch contract with an extra
	// inherited descriptor at fd 4 (on both macOS and Linux via RunStage).
	proc, err := confine.StartStage(exe, nil, StageSpec{
		Version:    SpecVersion,
		Policy:     DefaultPolicy(exe),
		WorkerPath: exe,
		WorkerArgs: []string{extraFDMarker},
	}, pr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Close() }()

	if f, ok := proc.Conn.(*os.File); ok {
		_ = f.SetDeadline(time.Now().Add(5 * time.Second))
	}
	line, err := bufio.NewReader(proc.Conn).ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatalf("read from StartStage worker: %v (stderr: %s)", err, proc.Stderr())
	}
	if got := strings.TrimSpace(line); got != "extra:inherited-fd4-ok" {
		t.Fatalf("StartStage worker output = %q, want %q (stderr: %s)", got, "extra:inherited-fd4-ok", proc.Stderr())
	}
}

func TestZeroPolicyIsClosed(t *testing.T) {
	var zero Policy
	if zero.AllowUnsandboxed {
		t.Fatal("zero policy must not allow unsandboxed execution")
	}
	if err := zero.Validate(); err == nil {
		t.Fatal("zero policy must fail Validate")
	}
	pol := DefaultPolicy("/bin/echo", "/tmp")
	if pol.AllowUnsandboxed {
		t.Fatal("DefaultPolicy must not set AllowUnsandboxed")
	}
	if len(pol.WritePaths) != 0 {
		t.Fatalf("DefaultPolicy must have empty WritePaths, got %v", pol.WritePaths)
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("DefaultPolicy failed Validate: %v", err)
	}
}

func TestProbeReportsPlatformSupport(t *testing.T) {
	sup := Probe()
	switch runtime.GOOS {
	case "darwin":
		if !sup.Deprecated {
			t.Fatal("macOS sandbox-exec must be marked Deprecated")
		}
		if sup.Available && sup.Mechanism != MechanismSandboxExec {
			t.Fatalf("macOS mechanism = %q, want %q", sup.Mechanism, MechanismSandboxExec)
		}
	case "linux":
		if sup.Available {
			if sup.Mechanism != MechanismLandlock || sup.LandlockABI < 3 {
				t.Fatalf("linux support = %+v", sup)
			}
		}
	default:
		if sup.Available || sup.Mechanism != MechanismNone {
			t.Fatalf("unexpected support on %s: %+v", runtime.GOOS, sup)
		}
	}
}

func TestVerifyBinaryChecksPermissions(t *testing.T) {
	if _, err := VerifyBinary(""); err == nil {
		t.Fatal("empty path must fail")
	}
	dir := t.TempDir()
	if _, err := VerifyBinary(dir); err == nil {
		t.Fatal("directory must fail VerifyBinary")
	}
	if _, err := VerifyBinary(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail VerifyBinary")
	}

	bin := filepath.Join(dir, "worker")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if _, err := VerifyBinary(bin); err == nil {
			t.Fatal("non-executable file must fail VerifyBinary on Unix")
		}
		if err := os.Chmod(bin, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBinary(bin); err == nil {
			t.Fatal("world-writable binary must fail VerifyBinary on Unix")
		}
		if err := os.Chmod(bin, 0o775); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBinary(bin); err == nil {
			t.Fatal("group-writable binary must fail VerifyBinary on Unix")
		}
		if err := os.Chmod(bin, 0o755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBinary(bin); err == nil {
			t.Fatal("setuid binary must fail VerifyBinary on Unix")
		}
		if err := os.Chmod(bin, 0o755|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBinary(bin); err == nil {
			t.Fatal("setgid binary must fail VerifyBinary on Unix")
		}
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := VerifyBinary(bin)
	if err != nil {
		t.Fatalf("valid binary rejected: %v", err)
	}
	if resolved == "" {
		t.Fatal("empty resolved path")
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		badDir := filepath.Join(dir, "worldwritable")
		if err := os.Mkdir(badDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(badDir, 0o777); err != nil {
			t.Fatal(err)
		}
		badBin := filepath.Join(badDir, "worker")
		if err := os.WriteFile(badBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBinary(badBin); err == nil {
			t.Fatal("binary in world-writable non-sticky directory must fail VerifyBinary")
		}
	}
}

func TestResolveSiblingRejectsPaths(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../sh", "a/b", `a\b`} {
		if _, err := ResolveSibling(bad); err == nil {
			t.Errorf("ResolveSibling(%q) succeeded", bad)
		}
	}
	if _, err := ResolveSibling("definitely-missing-sibling-binary"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ResolveSibling missing = %v, want os.ErrNotExist", err)
	}
}

func TestPolicyValidateRejectsRelativeAndControlChars(t *testing.T) {
	for _, bad := range []string{
		"",
		"relative/path",
		"./worker",
		"/tmp/bad\x00path",
		"/tmp/bad\npath",
		"/tmp/bad\rpath",
		"/tmp/bad\x1bpath",
		"/tmp/bad\x7fpath",
		"/tmp/bad\u0085path",
		"/tmp/bad\xffpath",
	} {
		pol := Policy{ExecPaths: []string{bad}}
		if err := pol.Validate(); err == nil {
			t.Errorf("Policy.Validate accepted ExecPath %q", bad)
		}
		pol = Policy{ExecPaths: []string{"/bin/echo"}, ReadPaths: []string{bad}}
		if err := pol.Validate(); err == nil {
			t.Errorf("Policy.Validate accepted ReadPath %q", bad)
		}
		if _, err := VerifyBinary(bad); err == nil {
			t.Errorf("VerifyBinary accepted %q", bad)
		}
	}
}

func TestDefaultLibPathsNarrowsHomebrew(t *testing.T) {
	for _, p := range DefaultLibPaths() {
		if p == "/opt/homebrew" || p == "/usr/local" || strings.HasPrefix(p, "/opt/homebrew/var") || strings.HasPrefix(p, "/opt/homebrew/etc") {
			t.Fatalf("DefaultLibPaths exposes broad or sensitive path %q", p)
		}
	}
}

func TestDefaultExecPathsAreNarrowFiles(t *testing.T) {
	for _, p := range DefaultExecPaths() {
		switch p {
		case "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/usr/bin":
			t.Fatalf("DefaultExecPaths grants execute on broad directory %q", p)
		}
	}
}

func TestRustDefaultPathsMatchGo(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("unix default paths test")
	}
	raw, err := os.ReadFile(filepath.Join("rust", "ntconfine-client", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, p := range DefaultLibPaths() {
		needle := fmt.Sprintf("%q.into()", p)
		if !strings.Contains(src, needle) {
			t.Errorf("rust/ntconfine-client/src/lib.rs missing DefaultLibPaths entry %s", needle)
		}
	}
	for _, p := range DefaultExecPaths() {
		needle := fmt.Sprintf("%q.into()", p)
		if !strings.Contains(src, needle) {
			t.Errorf("rust/ntconfine-client/src/lib.rs missing DefaultExecPaths entry %s", needle)
		}
	}
	for _, forbidden := range []string{
		`"/usr/share".into()`,
		`"/opt/homebrew/share".into()`,
		`"/usr/local/share".into()`,
		`"/etc/localtime".into()`,
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("rust/ntconfine-client/src/lib.rs still contains broad path %s", forbidden)
		}
	}
}

func evalSeccompBPF(t *testing.T, prog []sockFilter, nr, arch, arg0Lo, arg0Hi, arg1Lo, arg2Lo uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); {
		ins := prog[pc]
		switch ins.Code {
		case bpfLD | bpfW | bpfABS:
			switch ins.K {
			case seccompOffNr:
				acc = nr
			case seccompOffArch:
				acc = arch
			case seccompOffArg0Lo:
				acc = arg0Lo
			case seccompOffArg0Hi:
				acc = arg0Hi
			case seccompOffArg1Lo:
				acc = arg1Lo
			case seccompOffArg2Lo:
				acc = arg2Lo
			default:
				t.Fatalf("unsupported BPF load offset %d", ins.K)
			}
			pc++
		case bpfJMP | bpfJEQ | bpfK:
			if acc == ins.K {
				pc += 1 + int(ins.JT)
			} else {
				pc += 1 + int(ins.JF)
			}
		case bpfJMP | bpfJGE | bpfK:
			if acc >= ins.K {
				pc += 1 + int(ins.JT)
			} else {
				pc += 1 + int(ins.JF)
			}
		case bpfJMP | bpfJSET | bpfK:
			if acc&ins.K != 0 {
				pc += 1 + int(ins.JT)
			} else {
				pc += 1 + int(ins.JF)
			}
		case bpfRET | bpfK:
			return ins.K
		default:
			t.Fatalf("unsupported BPF opcode %#x at pc=%d", ins.Code, pc)
		}
	}
	t.Fatal("BPF program fell off the end")
	return 0
}

func TestSeccompBPFSimulator(t *testing.T) {
	const (
		nrRead     = 0
		nrOpen     = 2
		nrIoctl    = 16
		nrClone    = 56
		nrKill     = 62
		nrTkill    = 200
		nrTgkill   = 234
		nrOpenat   = 257
		nrUnshare  = 272
		nrClone3   = 435
		fionbio    = 0x5421
		selfPID    = 4242
		epermCode  = 1
		enosysCode = 38
	)
	denied := []uintptr{nrKill, nrUnshare}
	prog := compileSeccompProgram(denied, nrClone, nrClone3, nrOpen, nrOpenat, nrIoctl, nrTgkill, nrTkill, auditArchX8664, selfPID, epermCode, enosysCode)
	wantEperm := uint32(seccompRetErrno | epermCode)
	wantEnosys := uint32(seccompRetErrno | enosysCode)

	if got := evalSeccompBPF(t, prog, nrRead, auditArchAArch64, 0, 0, 0, 0); got != seccompRetKill {
		t.Fatalf("wrong arch = %#x, want %#x", got, seccompRetKill)
	}
	if got := evalSeccompBPF(t, prog, x32Bit|nrRead, auditArchX8664, 0, 0, 0, 0); got != seccompRetKill {
		t.Fatalf("x32 syscall = %#x, want %#x", got, seccompRetKill)
	}
	for _, nr := range []uint32{nrKill, nrUnshare} {
		if got := evalSeccompBPF(t, prog, nr, auditArchX8664, 0, 0, 0, 0); got != wantEperm {
			t.Fatalf("denied syscall %d = %#x, want %#x", nr, got, wantEperm)
		}
	}
	if got := evalSeccompBPF(t, prog, nrClone3, auditArchX8664, 0, 0, 0, 0); got != wantEnosys {
		t.Fatalf("clone3 = %#x, want %#x (ENOSYS)", got, wantEnosys)
	}
	if got := evalSeccompBPF(t, prog, nrOpen, auditArchX8664, 0, 0, oTruncMask, 0); got != wantEperm {
		t.Fatalf("open(O_TRUNC) = %#x, want %#x", got, wantEperm)
	}
	if got := evalSeccompBPF(t, prog, nrOpen, auditArchX8664, 0, 0, 0, 0); got != seccompRetAllow {
		t.Fatalf("open(O_RDONLY) = %#x, want %#x", got, seccompRetAllow)
	}
	if got := evalSeccompBPF(t, prog, nrOpenat, auditArchX8664, 0, 0, 0, oTruncMask); got != wantEperm {
		t.Fatalf("openat(O_TRUNC) = %#x, want %#x", got, wantEperm)
	}
	if got := evalSeccompBPF(t, prog, nrOpenat, auditArchX8664, 0, 0, 0, 0); got != seccompRetAllow {
		t.Fatalf("openat(O_RDONLY) = %#x, want %#x", got, seccompRetAllow)
	}
	for _, cmd := range []uint32{ioctlFsSetFlags64, ioctlFsSetFlags32, ioctlFsSetXattr, ioctlTiocsti} {
		if got := evalSeccompBPF(t, prog, nrIoctl, auditArchX8664, 3, 0, cmd, 0); got != wantEperm {
			t.Fatalf("ioctl(%#x) = %#x, want %#x", cmd, got, wantEperm)
		}
	}
	if got := evalSeccompBPF(t, prog, nrIoctl, auditArchX8664, 3, 0, fionbio, 0); got != seccompRetAllow {
		t.Fatalf("ioctl(FIONBIO) = %#x, want %#x", got, seccompRetAllow)
	}
	for _, flag := range []uint32{0x10000000, 0x00020000, 0x20000000, 0x40000000, 0x00000080} {
		if got := evalSeccompBPF(t, prog, nrClone, auditArchX8664, flag, 0, 0, 0); got != wantEperm {
			t.Fatalf("clone with flag %#x = %#x, want %#x", flag, got, wantEperm)
		}
	}
	if got := evalSeccompBPF(t, prog, nrClone, auditArchX8664, 0x00010f00, 0, 0, 0); got != seccompRetAllow {
		t.Fatalf("thread clone = %#x, want %#x", got, seccompRetAllow)
	}
	for _, nr := range []uint32{nrTgkill, nrTkill} {
		if got := evalSeccompBPF(t, prog, nr, auditArchX8664, selfPID, 0, 0, 0); got != seccompRetAllow {
			t.Fatalf("syscall %d(selfPID) = %#x, want %#x", nr, got, seccompRetAllow)
		}
		if got := evalSeccompBPF(t, prog, nr, auditArchX8664, selfPID-1, 0, 0, 0); got != wantEperm {
			t.Fatalf("syscall %d(otherPID) = %#x, want %#x", nr, got, wantEperm)
		}
		if got := evalSeccompBPF(t, prog, nr, auditArchX8664, selfPID, 1, 0, 0); got != wantEperm {
			t.Fatalf("syscall %d(high bits) = %#x, want %#x", nr, got, wantEperm)
		}
	}
	if got := evalSeccompBPF(t, prog, nrRead, auditArchX8664, 0, 0, 0, 0); got != seccompRetAllow {
		t.Fatalf("read = %#x, want %#x", got, seccompRetAllow)
	}
}

func TestHelperCapturesSanitizedStderrAndCloses(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	pol := DefaultPolicy(exe)
	pol.AllowUnsandboxed = true

	helper, err := StartHelper(HelperConfig{
		Policy:     pol,
		WorkerPath: exe,
		WorkerArgs: []string{stderrMarker},
		StagePath:  exe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := helper.Conn.(*os.File); ok {
		_ = f.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if _, err := bufio.NewReader(helper.Conn).ReadString('\n'); err != nil {
		t.Fatalf("read ready line: %v", err)
	}
	_ = helper.Close()
	if got := helper.Stderr(); !strings.Contains(got, "worker-stderr") || strings.Contains(got, "\x1b") {
		t.Fatalf("helper.Stderr() = %q, want control-stripped worker-stderr", got)
	}
}

func TestHelperTransportSupportsDeadlineAndCloseUnblocksRead(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("unix socketpair transport test")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	pol := DefaultPolicy(exe)
	pol.AllowUnsandboxed = true

	helper, err := StartHelper(HelperConfig{
		Policy:     pol,
		WorkerPath: exe,
		WorkerArgs: []string{sleepMarker},
		StagePath:  exe,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = helper.Close() }()

	f, ok := helper.Conn.(*os.File)
	if !ok {
		t.Fatalf("helper.Conn = %T, want *os.File", helper.Conn)
	}
	if err := f.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline on socketpair failed: %v", err)
	}
	if err := f.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing SetWriteDeadline failed: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := helper.Conn.Read(buf[:])
		readDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := helper.Conn.Close(); err != nil {
		t.Fatalf("helper.Conn.Close: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected Read on closed helper.Conn to fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper.Conn.Close() did not unblock concurrent Read()")
	}
}

func TestCommandDoesNotPutPolicyPathsOnCommandLine(t *testing.T) {
	if !Available() {
		t.Skip("OS enforcement unavailable here")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	secretPath := "/tmp/nonexistent-secret-input-file-998877.dat"
	pol := DefaultPolicy(exe, secretPath)
	cmd, sup, err := Command(HelperConfig{
		Policy:     pol,
		WorkerPath: exe,
		StagePath:  exe,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range cmd.ExtraFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	if !sup.Available {
		t.Fatal("expected Command Support.Available == true")
	}
	for _, arg := range cmd.Args {
		if strings.Contains(arg, "nonexistent-secret-input-file") {
			t.Fatalf("Command exposed policy path in argv: %q", arg)
		}
		if len(arg) > 256 {
			t.Fatalf("Command passed large inline token (%d bytes) in argv", len(arg))
		}
	}
}

func FuzzPolicyValidate(f *testing.F) {
	f.Add("/bin/echo", "/tmp", "/var/tmp")
	f.Add("relative/path", "/tmp/bad\npath", "/tmp/bad\x00path")
	f.Add("/usr/bin/true", "/opt/homebrew/lib", "/Library/Fonts")

	f.Fuzz(func(t *testing.T, execPath, readPath, writePath string) {
		pol := Policy{
			ExecPaths:  []string{execPath},
			ReadPaths:  []string{readPath},
			WritePaths: []string{writePath},
		}
		if err := pol.Validate(); err == nil {
			for _, p := range []string{execPath, readPath, writePath} {
				if !filepath.IsAbs(p) {
					t.Fatalf("Policy.Validate accepted non-absolute path %q", p)
				}
				for _, r := range p {
					if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
						t.Fatalf("Policy.Validate accepted control rune %U in %q", r, p)
					}
				}
			}
		}
	})
}
