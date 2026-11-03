// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

const (
	sysPidfdSendSignal = 424
	sysIOUringSetup    = 425
	sysIOUringEnter    = 426
	sysIOUringRegister = 427
	sysOpenTree        = 428
	sysMoveMount       = 429
	sysFsopen          = 430
	sysFsconfig        = 431
	sysFsmount         = 432
	sysFspick          = 433
	sysPidfdOpen       = 434
	sysClone3          = 435
	sysOpenat2         = 437
	sysPidfdGetfd      = 438
	sysProcessMadvise  = 440
	sysMountSetattr    = 442
	sysFchmodat2       = 452
)

// deniedBase are syscalls no confined worker may invoke after lockdown.
// Note: sysClone3 is handled separately in compileSeccompProgram with ENOSYS so
// glibc >= 2.34 pthread_create falls back to clone(2).
var deniedBase = append([]uintptr{
	syscall.SYS_PTRACE, syscall.SYS_MOUNT, syscall.SYS_UMOUNT2,
	sysInitModule, sysFinitModule, sysBPF, sysKexecLoad, sysKexecFileLoad,
	sysProcessVMReadv, sysProcessVMWritev,
	sysIOUringSetup, sysIOUringEnter, sysIOUringRegister, // route around socket filter and Landlock
	sysUnshare, sysSetns,
	sysOpenTree, sysMoveMount, sysFsopen, sysFsconfig, sysFsmount, sysFspick, sysMountSetattr,
	sysPivotRoot, sysChroot,
	sysAddKey, sysRequestKey, sysKeyctl,
	sysUserfaultfd, sysPerfEventOpen, sysKcmp,
}, metadataCalls...)

func auditArch() uint32 {
	if runtime.GOARCH == "arm64" {
		return auditArchAArch64
	}
	return auditArchX8664
}

func buildSeccompProgram(calls []uintptr, arch, selfPID uint32) []sockFilter {
	return compileSeccompProgram(
		calls,
		uint32(sysClone),
		uint32(sysClone3),
		uint32(sysOpen),
		uint32(sysOpenat),
		uint32(sysIoctl),
		uint32(sysTgkill),
		uint32(sysTkill),
		arch,
		selfPID,
		uint32(syscall.EPERM),
		uint32(syscall.ENOSYS),
	)
}

// denySyscalls installs a seccomp-bpf filter across all threads with TSYNC:
// a listed call fails with EPERM, tgkill/tkill are restricted to os.Getpid(),
// clone with namespace flags fails with EPERM, and a call from another
// architecture or ABI kills the process.
func denySyscalls(calls []uintptr) error {
	prog := buildSeccompProgram(calls, auditArch(), uint32(os.Getpid()))
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r, _, errno := syscall.RawSyscall(sysSeccomp, seccompSetModeFilter, seccompFilterTSync, uintptr(unsafe.Pointer(&fprog)))
	return tsyncResult(r, errno)
}

// tsyncResult checks seccomp's return value: with TSYNC, a positive return is
// the TID of a thread that could not be synchronized.
func tsyncResult(r uintptr, errno syscall.Errno) error {
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	if r != 0 {
		return fmt.Errorf("seccomp: thread %d not synchronized", r)
	}
	return nil
}
