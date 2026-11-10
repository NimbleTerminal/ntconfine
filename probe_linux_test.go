// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"os"
	"runtime"
	"syscall"
	"testing"
)

// platformProbe verifies that the Linux seccomp-bpf filter blocks io_uring,
// unshare, pidfd_open, pidfd_getfd, process_madvise, openat2, and cross-process
// tgkill with EPERM, returns ENOSYS for clone3, and allows self-directed
// tgkill(pid, tid, 0). It returns a non-nil error when all confinement
// invariants hold, or nil if any check failed.
func platformProbe() error {
	var params [120]byte
	if fd, _, errno := syscall.Syscall(nr("io_uring_setup"), 4, uintptrOf(&params), 0); errno == 0 {
		_ = syscall.Close(int(fd))
		return nil
	}
	if _, _, errno := syscall.Syscall(nr("clone3"), 0, 0, 0); errno != syscall.ENOSYS {
		return nil
	}
	for _, nr := range []uintptr{nr("unshare"), nr("pidfd_open"), nr("pidfd_getfd"), nr("process_madvise"), nr("openat2")} {
		if _, _, errno := syscall.Syscall(nr, 0, 0, 0); errno != syscall.EPERM {
			return nil
		}
	}
	for _, cmd := range []uintptr{ioctlFsSetFlags64, ioctlFsSetFlags32, ioctlFsSetXattr} {
		if _, _, errno := syscall.Syscall(nr("ioctl"), 0, cmd, uintptrOf(&params)); errno != syscall.EPERM {
			return nil
		}
	}
	if _, _, errno := syscall.Syscall(nr("tgkill"), uintptr(os.Getppid()), uintptr(os.Getppid()), 0); errno != syscall.EPERM {
		return nil
	}
	if _, _, errno := syscall.Syscall(nr("tgkill"), uintptr(os.Getpid()), uintptr(syscall.Gettid()), 0); errno != 0 {
		return nil
	}
	return syscall.EPERM
}

func TestSeccompTSyncFailureIsAnError(t *testing.T) {
	if err := tsyncResult(1234, 0); err == nil {
		t.Fatal("a thread that did not sync must be an error")
	}
	if err := tsyncResult(0, 0); err != nil {
		t.Fatal(err)
	}
}

// nr returns the running architecture's number for a syscall that must exist.
func nr(name string) uintptr {
	n, ok, err := syscallNR(runtime.GOARCH, name)
	if err != nil || !ok {
		panic("no syscall number for " + name)
	}
	return n
}

// TestSyscallTableMatchesGoSyscallPackage cross-checks the hand-maintained
// table against numbers the Go standard library publishes for this architecture.
func TestSyscallTableMatchesGoSyscallPackage(t *testing.T) {
	for name, want := range map[string]uintptr{
		"ptrace": syscall.SYS_PTRACE, "mount": syscall.SYS_MOUNT, "umount2": syscall.SYS_UMOUNT2,
		"ioctl": syscall.SYS_IOCTL, "socket": syscall.SYS_SOCKET, "clone": syscall.SYS_CLONE,
		"kill": syscall.SYS_KILL, "tkill": syscall.SYS_TKILL, "tgkill": syscall.SYS_TGKILL,
		"openat": syscall.SYS_OPENAT, "truncate": syscall.SYS_TRUNCATE, "fchmod": syscall.SYS_FCHMOD,
		"fchmodat": syscall.SYS_FCHMODAT, "fchown": syscall.SYS_FCHOWN, "fchownat": syscall.SYS_FCHOWNAT,
		"setxattr": syscall.SYS_SETXATTR, "lsetxattr": syscall.SYS_LSETXATTR, "fsetxattr": syscall.SYS_FSETXATTR,
		"removexattr": syscall.SYS_REMOVEXATTR, "lremovexattr": syscall.SYS_LREMOVEXATTR,
		"fremovexattr": syscall.SYS_FREMOVEXATTR, "utimensat": syscall.SYS_UTIMENSAT,
		"unshare": syscall.SYS_UNSHARE, "pivot_root": syscall.SYS_PIVOT_ROOT, "chroot": syscall.SYS_CHROOT,
		"init_module": syscall.SYS_INIT_MODULE, "kexec_load": syscall.SYS_KEXEC_LOAD,
		"add_key": syscall.SYS_ADD_KEY, "request_key": syscall.SYS_REQUEST_KEY, "keyctl": syscall.SYS_KEYCTL,
		"rt_sigqueueinfo": syscall.SYS_RT_SIGQUEUEINFO, "rt_tgsigqueueinfo": syscall.SYS_RT_TGSIGQUEUEINFO,
		"perf_event_open": syscall.SYS_PERF_EVENT_OPEN,
	} {
		if got := nr(name); got != want {
			t.Errorf("syscallTable[%s][%q] = %d, want %d", runtime.GOARCH, name, got, want)
		}
	}
}
