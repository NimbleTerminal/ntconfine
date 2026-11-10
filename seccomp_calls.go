// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import "fmt"

// This file is the single source of truth for the Linux seccomp deny list. It
// has no build constraint so every platform can check it and render it into
// SECURITY.md (see securitydoc_test.go and `task security-doc`).

// deniedGroup is a documented category of syscalls denied with EPERM.
type deniedGroup struct {
	Title string
	Calls []string
}

// deniedGroups lists every syscall a confined worker may not invoke after the
// stage locks down. clone3 is deliberately absent: it returns ENOSYS so glibc
// >= 2.34 pthread_create falls back to clone(2), whose flags are inspected.
// execve stays allowed so the stage can exec the worker; Landlock restricts
// execution to Policy.ExecPaths. tgkill and tkill are filtered by PID instead.
var deniedGroups = []deniedGroup{
	{"Network and IPC", []string{
		"socket", "openat2",
	}},
	{"Cross-process signals and FD/memory inspection", []string{
		"kill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal",
		"pidfd_open", "pidfd_getfd", "process_vm_readv", "process_vm_writev",
		"process_madvise", "ptrace", "kcmp",
	}},
	{"Namespaces, mounts, and root changes", []string{
		"unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
		"mount_setattr",
	}},
	{"Kernel attack surface and keyrings", []string{
		"init_module", "finit_module", "bpf",
		"io_uring_setup", "io_uring_enter", "io_uring_register", // route around socket filter and Landlock
		"userfaultfd", "perf_event_open", "kexec_load", "kexec_file_load",
		"keyctl", "add_key", "request_key",
	}},
	// These mutate file metadata without opening the file, which Landlock
	// cannot mediate.
	{"Filesystem metadata mutation", []string{
		"truncate",
		"chmod", "fchmod", "fchmodat", "fchmodat2",
		"chown", "lchown", "fchown", "fchownat",
		"utime", "utimes", "futimesat", "utimensat",
		"setxattr", "lsetxattr", "fsetxattr",
		"removexattr", "lremovexattr", "fremovexattr",
	}},
}

// syscallAbsent names legacy syscalls that do not exist on an architecture, so
// a name missing from syscallTable is a hard error rather than a silent gap.
var syscallAbsent = map[string][]string{
	"arm64": {"open", "chmod", "chown", "lchown", "utime", "utimes", "futimesat"},
}

// syscallTable maps syscall names to numbers per GOARCH, from
// arch/x86/entry/syscalls/syscall_64.tbl and asm-generic/unistd.h.
var syscallTable = map[string]map[string]uintptr{
	"amd64": {
		"open": 2, "ioctl": 16, "socket": 41, "clone": 56, "kill": 62,
		"truncate": 76, "chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93,
		"lchown": 94, "ptrace": 101, "rt_sigqueueinfo": 129, "utime": 132,
		"pivot_root": 155, "chroot": 161, "mount": 165, "umount2": 166,
		"init_module": 175, "setxattr": 188, "lsetxattr": 189, "fsetxattr": 190,
		"removexattr": 197, "lremovexattr": 198, "fremovexattr": 199,
		"tkill": 200, "tgkill": 234, "utimes": 235, "kexec_load": 246,
		"add_key": 248, "request_key": 249, "keyctl": 250, "openat": 257,
		"fchownat": 260, "futimesat": 261, "fchmodat": 268, "unshare": 272,
		"utimensat": 280, "rt_tgsigqueueinfo": 297, "perf_event_open": 298,
		"setns": 308, "process_vm_readv": 310, "process_vm_writev": 311,
		"kcmp": 312, "finit_module": 313, "seccomp": 317,
		"kexec_file_load": 320, "bpf": 321, "userfaultfd": 323,
		"pidfd_send_signal": 424, "io_uring_setup": 425, "io_uring_enter": 426,
		"io_uring_register": 427, "open_tree": 428, "move_mount": 429,
		"fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
		"pidfd_open": 434, "clone3": 435, "openat2": 437, "pidfd_getfd": 438,
		"process_madvise": 440, "mount_setattr": 442, "fchmodat2": 452,
	},
	"arm64": {
		"setxattr": 5, "lsetxattr": 6, "fsetxattr": 7, "removexattr": 14,
		"lremovexattr": 15, "fremovexattr": 16, "ioctl": 29, "umount2": 39,
		"mount": 40, "pivot_root": 41, "truncate": 45, "chroot": 51,
		"fchmod": 52, "fchmodat": 53, "fchownat": 54, "fchown": 55,
		"openat": 56, "utimensat": 88, "unshare": 97, "kexec_load": 104,
		"init_module": 105, "ptrace": 117, "kill": 129, "tkill": 130,
		"tgkill": 131, "rt_sigqueueinfo": 138, "socket": 198, "add_key": 217,
		"request_key": 218, "keyctl": 219, "clone": 220,
		"rt_tgsigqueueinfo": 240, "perf_event_open": 241, "setns": 268,
		"process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272,
		"finit_module": 273, "seccomp": 277, "bpf": 280, "userfaultfd": 282,
		"kexec_file_load":   294,
		"pidfd_send_signal": 424, "io_uring_setup": 425, "io_uring_enter": 426,
		"io_uring_register": 427, "open_tree": 428, "move_mount": 429,
		"fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
		"pidfd_open": 434, "clone3": 435, "openat2": 437, "pidfd_getfd": 438,
		"process_madvise": 440, "mount_setattr": 442, "fchmodat2": 452,
	},
}

// noSyscall marks a syscall that does not exist on the target architecture.
const noSyscall = ^uint32(0)

// syscallNR returns the number of the named syscall on arch. ok is false with
// a nil error when the syscall is known not to exist there; an unknown
// architecture or an unlisted name is an error.
func syscallNR(arch, name string) (nr uintptr, ok bool, err error) {
	table, found := syscallTable[arch]
	if !found {
		return 0, false, fmt.Errorf("ntconfine: no syscall table for GOARCH %q", arch)
	}
	if nr, found = table[name]; found {
		return nr, true, nil
	}
	for _, absent := range syscallAbsent[arch] {
		if absent == name {
			return 0, false, nil
		}
	}
	return 0, false, fmt.Errorf("ntconfine: syscall %q has no number for GOARCH %q", name, arch)
}

// deniedSyscalls resolves deniedGroups to syscall numbers for arch.
func deniedSyscalls(arch string) ([]uintptr, error) {
	var out []uintptr
	for _, g := range deniedGroups {
		for _, name := range g.Calls {
			nr, ok, err := syscallNR(arch, name)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, nr)
			}
		}
	}
	return out, nil
}

// filterSyscalls holds the syscalls the seccomp program inspects by argument.
type filterSyscalls struct {
	clone, clone3, open, openat, ioctl, tgkill, tkill uint32
}

// argFilteredSyscalls resolves the argument-inspected syscalls for arch. Only
// open may be absent (noSyscall); every other one is required.
func argFilteredSyscalls(arch string) (filterSyscalls, error) {
	var f filterSyscalls
	for _, e := range []struct {
		name     string
		dst      *uint32
		optional bool
	}{
		{"clone", &f.clone, false},
		{"clone3", &f.clone3, false},
		{"open", &f.open, true},
		{"openat", &f.openat, false},
		{"ioctl", &f.ioctl, false},
		{"tgkill", &f.tgkill, false},
		{"tkill", &f.tkill, false},
	} {
		nr, ok, err := syscallNR(arch, e.name)
		switch {
		case err != nil:
			return f, err
		case ok:
			*e.dst = uint32(nr)
		case e.optional:
			*e.dst = noSyscall
		default:
			return f, fmt.Errorf("ntconfine: required syscall %q is absent for GOARCH %q", e.name, arch)
		}
	}
	return f, nil
}

// Linux errno values returned by the filter, spelled out so the program can be
// built and simulated on any host OS.
const (
	linuxEPERM  = 1
	linuxENOSYS = 38
)

// buildSeccompProgram compiles the stage filter for goarch from deniedGroups
// and the argument-inspected syscalls above.
func buildSeccompProgram(goarch string, arch, selfPID uint32) ([]sockFilter, error) {
	denied, err := deniedSyscalls(goarch)
	if err != nil {
		return nil, err
	}
	f, err := argFilteredSyscalls(goarch)
	if err != nil {
		return nil, err
	}
	return compileSeccompProgram(denied, f.clone, f.clone3, f.open, f.openat, f.ioctl, f.tgkill, f.tkill,
		arch, selfPID, linuxEPERM, linuxENOSYS), nil
}
