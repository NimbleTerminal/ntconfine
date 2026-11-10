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

func auditArch() uint32 {
	if runtime.GOARCH == "arm64" {
		return auditArchAArch64
	}
	return auditArchX8664
}

// denySyscalls installs the stage seccomp-bpf filter across all threads with
// TSYNC: a call listed in deniedGroups fails with EPERM, clone3 fails with
// ENOSYS, tgkill/tkill are restricted to os.Getpid(), clone with namespace
// flags fails with EPERM, and a call from another architecture or ABI kills
// the process.
func denySyscalls() error {
	prog, err := buildSeccompProgram(runtime.GOARCH, auditArch(), uint32(os.Getpid()))
	if err != nil {
		return err
	}
	sysSeccomp, ok, err := syscallNR(runtime.GOARCH, "seccomp")
	if err != nil || !ok {
		return fmt.Errorf("ntconfine: seccomp syscall unavailable: %v", err)
	}
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
