// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

// Landlock constants from linux/landlock.h and asm-generic/unistd.h.
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	landlockCreateRulesetVersion = 1 << 0
	landlockRulePathBeneath      = 1

	accessExecute     = 1 << 0
	accessWriteFile   = 1 << 1
	accessReadFile    = 1 << 2
	accessReadDir     = 1 << 3
	accessRemoveDir   = 1 << 4
	accessRemoveFile  = 1 << 5
	accessMakeChar    = 1 << 6
	accessMakeDir     = 1 << 7
	accessMakeReg     = 1 << 8
	accessMakeSock    = 1 << 9
	accessMakeFifo    = 1 << 10
	accessMakeBlock   = 1 << 11
	accessMakeSym     = 1 << 12
	accessRefer       = 1 << 13
	accessTruncate    = 1 << 14
	accessIoctlDev    = 1 << 15
	accessResolveUnix = 1 << 16

	accessFS    = (1 << 17) - 1
	accessRead  = accessReadFile | accessReadDir
	accessDirRW = accessRead | accessWriteFile | accessRemoveDir | accessRemoveFile |
		accessMakeReg | accessMakeDir | accessMakeSym | accessRefer | accessTruncate
	accessFileRW = accessReadFile | accessWriteFile | accessTruncate

	netBindTCP    = 1 << 0
	netConnectTCP = 1 << 1
	netBindUDP    = 1 << 2
	netConnectUDP = 1 << 3
	accessNetTCP  = netBindTCP | netConnectTCP
	accessNetAll  = accessNetTCP | netBindUDP | netConnectUDP

	scopeAbstractUnixSocket = 1 << 0
	scopeSignal             = 1 << 1
	scopeAll                = scopeAbstractUnixSocket | scopeSignal

	// minLandlockABI is the lowest Landlock ABI accepted (Linux 6.2). ABI 3
	// added LANDLOCK_ACCESS_FS_TRUNCATE; older kernels fail closed as unavailable.
	minLandlockABI = 3

	prSetNoNewPrivs = 38
	fSetPipeSz      = 1031 // F_SETPIPE_SZ
	oPath           = 0x200000

	rlimitNproc            = 6
	defaultMaxAddressSpace = 16 << 30 // 16 GiB virtual address space ceiling
	defaultMaxOpenFiles    = 1024
	defaultMaxProcesses    = 4096 // per-UID task ceiling on Linux (matches Policy doc)
)

var fsMaskForABI = [...]uint64{
	1:  (1 << 13) - 1,
	2:  (1 << 14) - 1,
	3:  (1 << 15) - 1,
	4:  (1 << 15) - 1,
	5:  (1 << 16) - 1,
	6:  (1 << 16) - 1,
	7:  (1 << 16) - 1,
	8:  (1 << 16) - 1,
	9:  (1 << 16) - 1 | accessResolveUnix,
	10: (1 << 16) - 1 | accessResolveUnix,
}

type rulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
	scoped           uint64
}

type pathBeneathAttr struct {
	allowedAccess uint64
	parentFD      int32
	_             [4]byte
}

func landlockABI() int {
	v, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return 0
	}
	return int(v)
}

func socketpairCloexec() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
		syscall.ForkLock.RLock()
		fds, err = syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err == nil {
			syscall.CloseOnExec(fds[0])
			syscall.CloseOnExec(fds[1])
		}
		syscall.ForkLock.RUnlock()
	}
	return fds, err
}

var availableOnce = sync.OnceValue(func() bool { return landlockABI() >= minLandlockABI })

// Available reports whether the running Linux kernel supports Landlock ABI 3
// or newer (Linux 6.2+).
func Available() bool { return availableOnce() }

// Probe reports the Linux Landlock + seccomp capability of the current host.
func Probe() Support {
	abi := landlockABI()
	if abi >= minLandlockABI {
		capped := min(abi, len(fsMaskForABI)-1)
		detail := fmt.Sprintf("Linux Landlock ABI v%d + seccomp-bpf (TSYNC; FS_TRUNCATE + seccomp truncate/O_TRUNC filter)", capped)
		return Support{
			Available:   true,
			Mechanism:   MechanismLandlock,
			LandlockABI: capped,
			Deprecated:  false,
			Detail:      detail,
		}
	}
	detail := "Linux Landlock is unavailable on this kernel"
	if abi >= 1 {
		detail = fmt.Sprintf("Linux Landlock ABI v%d is too old (ABI v%d / Linux 6.2 or newer is required)", abi, minLandlockABI)
	}
	return Support{
		Available:  false,
		Mechanism:  MechanismNone,
		Deprecated: false,
		Detail:     detail,
	}
}

// DefaultLibPaths returns the default shared-library and fontconfig/font search
// directories for a confined worker on Linux.
func DefaultLibPaths() []string {
	return []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/usr/local/lib",
		"/etc/ld.so.cache",
		"/etc/fonts",
		"/usr/share/fonts",
		"/usr/local/share/fonts",
		"/var/cache/fontconfig",
	}
}

// DefaultExecPaths returns the default dynamic loader file paths on Linux.
// On Linux, execve of a dynamically linked ELF binary requires execute access
// on both the binary and its PT_INTERP dynamic loader. Only the literal loader
// files (not library directories) are listed so arbitrary binaries under
// /usr/lib cannot be executed.
func DefaultExecPaths() []string {
	return []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"/usr/lib64/ld-linux-x86-64.so.2",
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"/lib/ld-linux-aarch64.so.1",
		"/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
		"/usr/lib/ld-linux-aarch64.so.1",
		"/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
		"/lib/ld-musl-x86_64.so.1",
		"/lib/ld-musl-aarch64.so.1",
	}
}

type ruleset struct {
	fd   int
	mask uint64
}

func newRuleset(denyNet bool) (*ruleset, error) {
	abi := min(landlockABI(), len(fsMaskForABI)-1)
	if abi < minLandlockABI {
		return nil, ErrUnavailable
	}
	for {
		attr := rulesetAttr{handledAccessFS: fsMaskForABI[abi]}
		size := unsafe.Sizeof(attr.handledAccessFS)
		if abi >= 4 {
			if denyNet {
				if abi >= 10 {
					attr.handledAccessNet = accessNetAll
				} else {
					attr.handledAccessNet = accessNetTCP
				}
			}
			size += unsafe.Sizeof(attr.handledAccessNet)
		}
		if abi >= 6 {
			attr.scoped = scopeAll
			size += unsafe.Sizeof(attr.scoped)
		}
		fd, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), size, 0)
		if errno == 0 {
			return &ruleset{fd: int(fd), mask: attr.handledAccessFS}, nil
		}
		if errno == syscall.EINVAL && abi > 6 {
			abi = 6
			continue
		}
		return nil, fmt.Errorf("landlock create ruleset: %w", errno)
	}
}

func (r *ruleset) add(path string, access uint64) error {
	if path == "" {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("landlock open %s: %w", path, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		access &= accessFileRW | accessExecute | accessIoctlDev
	}
	attr := pathBeneathAttr{allowedAccess: access & r.mask, parentFD: int32(fd)}
	_, _, errno := syscall.Syscall6(sysLandlockAddRule, uintptr(r.fd), landlockRulePathBeneath, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock add %s: %w", path, errno)
	}
	return nil
}

func (r *ruleset) restrict() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("prctl NO_NEW_PRIVS: %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(sysLandlockRestrictSelf, uintptr(r.fd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict: %w", errno)
	}
	_ = syscall.Close(r.fd)
	return nil
}

// maxInlinePipeSpecBytes is the StageSpec size that always fits the anonymous
// spec pipe before cmd.Start(). 4096 bytes matches Linux PIPE_BUF and the
// single-page minimum pipe capacity guaranteed even when pipe-user-pages-soft
// is exceeded. Larger specs first grow the pipe with F_SETPIPE_SZ so they can
// also be written synchronously, which avoids leaving a blocked goroutine and
// an open pipe behind when a Command(cfg) caller never starts the command.
const maxInlinePipeSpecBytes = 4096

func helperCommand(cfg HelperConfig, workerPath string, ephemeral bool) (*exec.Cmd, func(), error) {
	stagePath := cfg.StagePath
	var err error
	if stagePath == "" {
		stagePath, err = ResolveSibling(DefaultStageBinary)
	} else {
		stagePath, err = VerifyBinary(stagePath)
	}
	if err != nil {
		return nil, nil, err
	}
	pol := cfg.Policy
	if !slices.Contains(pol.ExecPaths, workerPath) {
		pol.ExecPaths = append(slices.Clone(pol.ExecPaths), workerPath)
	}
	specB64, err := EncodeStageSpec(StageSpec{
		Version:    SpecVersion,
		Policy:     pol,
		WorkerPath: workerPath,
		WorkerArgs: cfg.WorkerArgs,
	})
	if err != nil {
		return nil, nil, err
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	inline := len(specB64) <= maxInlinePipeSpecBytes
	if !inline {
		// Grow the pipe to hold the whole spec so the write below cannot block.
		// If the kernel refuses (per-user pipe page limits), fall back to a
		// background writer.
		sz, _, errno := syscall.Syscall(syscall.SYS_FCNTL, pw.Fd(), fSetPipeSz, uintptr(len(specB64)))
		inline = errno == 0 && int(sz) >= len(specB64)
	}
	if inline {
		if _, err := io.WriteString(pw, specB64); err != nil {
			_ = pw.Close()
			_ = pr.Close()
			return nil, nil, err
		}
		_ = pw.Close()
	} else {
		go func() {
			_, _ = io.WriteString(pw, specB64)
			_ = pw.Close()
		}()
	}

	// StartHelper (ephemeral == true) prepends the worker socket at ExtraFiles[0]
	// (child fd 3), followed by cfg.ExtraFiles, followed by pr. Command(cfg)
	// (ephemeral == false) puts cfg.ExtraFiles followed by pr.
	baseFD := 3 + len(cfg.ExtraFiles)
	if ephemeral {
		baseFD++
	}
	fdArg := fmt.Sprintf("fd:%d", baseFD)
	args := make([]string, 0, len(cfg.StageArgs)+2)
	args = append(args, cfg.StageArgs...)
	args = append(args, StageArg, fdArg)
	cmd := exec.Command(stagePath, args...)
	extra := make([]*os.File, 0, len(cfg.ExtraFiles)+1)
	extra = append(extra, cfg.ExtraFiles...)
	extra = append(extra, pr)
	cmd.ExtraFiles = extra
	return cmd, nil, nil
}

// deniedHelper adds socket, pidfd/cross-process inspection, openat2, and signal
// delivery syscalls to the syscalls denied after stage lockdown. tgkill and
// tkill are filtered by PID in buildSeccompProgram so the Go runtime can signal
// its own threads while cross-process signaling is blocked even on kernels < 6.12
// without Landlock ABI 6. execve stays allowed so the stage can exec the worker;
// Landlock restricts execution to Policy.ExecPaths.
var deniedHelper = append([]uintptr{
	sysSocket,
	sysKill,
	sysRtSigqueueinfo,
	sysRtTgsigqueueinfo,
	sysPidfdSendSignal,
	sysPidfdOpen,
	sysPidfdGetfd,
	sysProcessMadvise,
	sysOpenat2,
}, deniedBase...)

// RunStage parses the encoded stage specification from args (either via an
// inherited pipe descriptor "fd:<N>" or an inline base64 token), confines all OS
// threads of the current process with Landlock, rlimits, and seccomp-bpf, and
// replaces the process with the target worker binary. It returns only on failure.
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

func setClampedRlimit(resource int, target uint64) error {
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(resource, &cur); err != nil {
		return fmt.Errorf("getrlimit(%d): %w", resource, err)
	}
	if cur.Max != ^uint64(0) && target > cur.Max {
		target = cur.Max
	}
	next := syscall.Rlimit{Cur: target, Max: target}
	if err := syscall.Setrlimit(resource, &next); err != nil {
		return fmt.Errorf("setrlimit(%d, %d): %w", resource, target, err)
	}
	return nil
}

func applyResourceLimits(pol Policy) error {
	if err := setClampedRlimit(syscall.RLIMIT_CORE, 0); err != nil {
		return err
	}
	nofile := pol.MaxOpenFiles
	if nofile == 0 {
		nofile = defaultMaxOpenFiles
	}
	if err := setClampedRlimit(syscall.RLIMIT_NOFILE, nofile); err != nil {
		return err
	}
	as := pol.MaxAddressSpace
	if as == 0 {
		as = defaultMaxAddressSpace
	}
	if err := setClampedRlimit(syscall.RLIMIT_AS, as); err != nil {
		return err
	}
	nproc := pol.MaxProcesses
	if nproc == 0 {
		nproc = defaultMaxProcesses
	}
	if err := setClampedRlimit(rlimitNproc, nproc); err != nil {
		return err
	}
	return nil
}

// RunStagePolicy confines all OS threads of the current process according to pol
// and replaces the process with workerPath. It returns only on failure before
// Landlock restrict(); after restrict() succeeds, any failure exits the process.
func RunStagePolicy(pol Policy, workerPath string, workerArgs []string) error {
	if err := pol.Validate(); err != nil {
		return err
	}
	resolvedWorker, err := VerifyBinary(workerPath)
	if err != nil {
		return err
	}
	if err := applyResourceLimits(pol); err != nil {
		return err
	}
	r, err := newRuleset(true)
	if err != nil {
		return err
	}
	for _, p := range pol.ReadPaths {
		if err := r.add(p, accessRead); err != nil {
			return err
		}
	}
	for _, p := range pol.WritePaths {
		if err := r.add(p, accessDirRW); err != nil {
			return err
		}
	}
	execPaths := pol.ExecPaths
	if !slices.Contains(execPaths, resolvedWorker) {
		execPaths = append(slices.Clone(execPaths), resolvedWorker)
	}
	for _, p := range execPaths {
		if err := r.add(p, accessRead|accessExecute); err != nil {
			return err
		}
	}
	if err := r.add("/dev/null", accessFileRW); err != nil {
		return err
	}
	if err := r.restrict(); err != nil {
		return err
	}
	// Once restrict() succeeds, NO_NEW_PRIVS and the Landlock domain are
	// irreversible on all threads. Never return to an in-process caller in a
	// half-confined state without the seccomp filter.
	if err := denySyscalls(deniedHelper); err != nil {
		fmt.Fprintln(os.Stderr, "ntconfine:", err)
		os.Exit(1)
	}
	argv := make([]string, 0, 1+len(workerArgs))
	argv = append(argv, resolvedWorker)
	argv = append(argv, workerArgs...)
	if err := syscall.Exec(resolvedWorker, argv, []string{}); err != nil {
		fmt.Fprintln(os.Stderr, "ntconfine: exec:", err)
		os.Exit(1)
	}
	return nil
}
