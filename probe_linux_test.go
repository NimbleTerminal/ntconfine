// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"os"
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
	if fd, _, errno := syscall.Syscall(sysIOUringSetup, 4, uintptrOf(&params), 0); errno == 0 {
		_ = syscall.Close(int(fd))
		return nil
	}
	if _, _, errno := syscall.Syscall(sysClone3, 0, 0, 0); errno != syscall.ENOSYS {
		return nil
	}
	for _, nr := range []uintptr{sysUnshare, sysPidfdOpen, sysPidfdGetfd, sysProcessMadvise, sysOpenat2} {
		if _, _, errno := syscall.Syscall(nr, 0, 0, 0); errno != syscall.EPERM {
			return nil
		}
	}
	for _, cmd := range []uintptr{ioctlFsSetFlags64, ioctlFsSetFlags32, ioctlFsSetXattr} {
		if _, _, errno := syscall.Syscall(sysIoctl, 0, cmd, uintptrOf(&params)); errno != syscall.EPERM {
			return nil
		}
	}
	if _, _, errno := syscall.Syscall(sysTgkill, uintptr(os.Getppid()), uintptr(os.Getppid()), 0); errno != syscall.EPERM {
		return nil
	}
	if _, _, errno := syscall.Syscall(sysTgkill, uintptr(os.Getpid()), uintptr(syscall.Gettid()), 0); errno != 0 {
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

func TestClone3NotInDeniedBase(t *testing.T) {
	for _, nr := range deniedBase {
		if nr == sysClone3 {
			t.Fatal("sysClone3 must not be in deniedBase (must return ENOSYS, not EPERM)")
		}
	}
}
