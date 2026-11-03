// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

// Classic BPF and seccomp constants from linux/filter.h and linux/seccomp.h.
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJGE  = 0x30
	bpfJSET = 0x40
	bpfK    = 0x00
	bpfRET  = 0x06

	seccompSetModeFilter = 1
	seccompFilterTSync   = 1
	seccompRetAllow      = 0x7fff0000
	seccompRetErrno      = 0x00050000
	seccompRetKill       = 0x80000000

	// Offsets in struct seccomp_data (little-endian amd64/arm64).
	seccompOffNr     = 0
	seccompOffArch   = 4
	seccompOffArg0Lo = 16
	seccompOffArg0Hi = 20
	seccompOffArg1Lo = 24
	seccompOffArg2Lo = 32

	// CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWTIME
	cloneNewMask = 0x7e020080

	// O_TRUNC (01000 octal = 0x200 on both x86_64 and arm64 Linux).
	oTruncMask = 0x200

	// ioctl(2) request codes that mutate inode flags or inject terminal input
	// on an O_RDONLY descriptor, which Landlock does not mediate on regular files.
	ioctlFsSetFlags64 = 0x40086602 // _IOW('f', 2, long)
	ioctlFsSetFlags32 = 0x40046602 // _IOW('f', 2, int)
	ioctlFsSetXattr   = 0x401c5820 // _IOW('X', 32, struct fsxattr)
	ioctlTiocsti      = 0x00005412 // TIOCSTI

	x32Bit = 0x40000000

	auditArchX8664   = 0xc000003e
	auditArchAArch64 = 0xc00000b7
)

type sockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

func compileSeccompProgram(calls []uintptr, cloneNR, clone3NR, openNR, openatNR, ioctlNR, tgkillNR, tkillNR, arch, selfPID, epermErrno, enosysErrno uint32) []sockFilter {
	eperm := seccompRetErrno | (epermErrno & 0xffff)
	enosys := seccompRetErrno | (enosysErrno & 0xffff)
	prog := []sockFilter{
		{Code: bpfLD | bpfW | bpfABS, K: seccompOffArch}, // seccomp_data.arch
		{Code: bpfJMP | bpfJEQ | bpfK, JT: 1, K: arch},
		{Code: bpfRET | bpfK, K: seccompRetKill},
		{Code: bpfLD | bpfW | bpfABS, K: seccompOffNr},   // seccomp_data.nr
		{Code: bpfJMP | bpfJGE | bpfK, JF: 1, K: x32Bit}, // x32 numbers would bypass checks below
		{Code: bpfRET | bpfK, K: seccompRetKill},
	}
	// Return ENOSYS for clone3(2) so glibc >= 2.34 pthread_create falls back to
	// legacy clone(2), where CLONE_NEW* namespace flags are inspected below.
	prog = append(prog,
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JF: 1, K: clone3NR},
		sockFilter{Code: bpfRET | bpfK, K: enosys},
	)
	for _, nr := range calls {
		prog = append(prog,
			sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JF: 1, K: uint32(nr)},
			sockFilter{Code: bpfRET | bpfK, K: eperm},
		)
	}
	// Block open(2) and openat(2) with O_TRUNC so a worker on Landlock ABI 1 or 2
	// (which lacks LANDLOCK_ACCESS_FS_TRUNCATE) cannot truncate readable files via
	// open(path, O_RDONLY|O_TRUNC).
	if openNR != ^uint32(0) {
		prog = append(prog,
			sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 4, K: openNR},
			sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg1Lo},
			sockFilter{Code: bpfJMP | bpfJSET | bpfK, JT: 0, JF: 1, K: oTruncMask},
			sockFilter{Code: bpfRET | bpfK, K: eperm},
			sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
		)
	}
	prog = append(prog,
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 4, K: openatNR},
		sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg2Lo},
		sockFilter{Code: bpfJMP | bpfJSET | bpfK, JT: 0, JF: 1, K: oTruncMask},
		sockFilter{Code: bpfRET | bpfK, K: eperm},
		sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
	)
	// Block ioctl(2) commands that mutate inode flags (FS_IOC_SETFLAGS,
	// FS_IOC32_SETFLAGS, FS_IOC_FSSETXATTR) or inject terminal input (TIOCSTI)
	// on an O_RDONLY descriptor, while permitting normal fd ioctls (FIONBIO).
	prog = append(prog,
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 7, K: ioctlNR},
		sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg1Lo},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 3, JF: 0, K: ioctlFsSetFlags64},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 2, JF: 0, K: ioctlFsSetFlags32},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 1, JF: 0, K: ioctlFsSetXattr},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 1, K: ioctlTiocsti},
		sockFilter{Code: bpfRET | bpfK, K: eperm},
		sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
	)
	// Block clone(2) with any CLONE_NEW* namespace creation flags in arg0.
	prog = append(prog,
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 4, K: cloneNR},
		sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg0Lo},
		sockFilter{Code: bpfJMP | bpfJSET | bpfK, JT: 0, JF: 1, K: cloneNewMask},
		sockFilter{Code: bpfRET | bpfK, K: eperm},
		sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
	)
	// Restrict tgkill(2) and tkill(2) so the worker can only signal its own PID
	// (closing cross-process signal delivery on kernels < 6.12 without Landlock ABI 6).
	prog = append(prog,
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 1, JF: 0, K: tgkillNR},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 5, K: tkillNR},
		sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg0Hi},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 0, JF: 2, K: 0},
		sockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompOffArg0Lo},
		sockFilter{Code: bpfJMP | bpfJEQ | bpfK, JT: 1, JF: 0, K: selfPID},
		sockFilter{Code: bpfRET | bpfK, K: eperm},
		sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
	)
	return prog
}
