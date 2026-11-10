// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

// This file is the single source of truth for the Linux Landlock rights, ABI
// thresholds, and stage rlimit defaults. It has no build constraint so every
// platform can check it and render it into SECURITY.md (see
// securitydoc_test.go and `task security-doc`).

// Landlock access rights from linux/landlock.h.
const (
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

	netBindTCP    = 1 << 0
	netConnectTCP = 1 << 1
	netBindUDP    = 1 << 2
	netConnectUDP = 1 << 3
	accessNetTCP  = netBindTCP | netConnectTCP
	accessNetAll  = accessNetTCP | netBindUDP | netConnectUDP

	scopeAbstractUnixSocket = 1 << 0
	scopeSignal             = 1 << 1
	scopeAll                = scopeAbstractUnixSocket | scopeSignal
)

// Rights granted by each kind of Policy path. Everything else Landlock handles
// is denied.
const (
	accessRead   = accessReadFile | accessReadDir
	accessFileRW = accessReadFile | accessWriteFile | accessTruncate

	// accessReadPath is granted beneath each Policy.ReadPaths entry.
	accessReadPath = accessRead
	// accessWritePath is granted beneath each Policy.WritePaths entry.
	accessWritePath = accessRead | accessWriteFile | accessRemoveDir | accessRemoveFile |
		accessMakeReg | accessMakeDir | accessMakeSym | accessRefer | accessTruncate
	// accessExecPath is granted on each Policy.ExecPaths entry and the worker.
	accessExecPath = accessRead | accessExecute
	// accessDevNull is granted on /dev/null.
	accessDevNull = accessFileRW
	// accessFileMask limits the rights requested for a path that is a file
	// rather than a directory, as Landlock requires.
	accessFileMask = accessFileRW | accessExecute | accessIoctlDev
)

// Landlock ABI thresholds.
const (
	// minLandlockABI is the lowest Landlock ABI accepted (Linux 6.2). ABI 3
	// added LANDLOCK_ACCESS_FS_TRUNCATE; older kernels fail closed as unavailable.
	minLandlockABI = 3
	// minLandlockKernel is the first Linux release with minLandlockABI.
	minLandlockKernel = "6.2"
	// netTCPMinABI is the first ABI that can deny TCP bind and connect.
	netTCPMinABI = 4
	// scopeMinABI is the first ABI with abstract Unix socket and signal scoping.
	scopeMinABI = 6
	// netUDPMinABI is the first ABI that can deny UDP bind and connect/send.
	netUDPMinABI = 10
	// fallbackABI is retried when a newer kernel rejects the requested rights.
	fallbackABI = 6
)

// fsMaskForABI is the set of filesystem rights handled at each Landlock ABI.
// Its last index is the highest ABI this package requests.
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

// Stage rlimit defaults, used when the matching Policy field is zero.
const (
	defaultMaxAddressSpace = 16 << 30 // RLIMIT_AS: 16 GiB virtual address space ceiling
	defaultMaxOpenFiles    = 1024     // RLIMIT_NOFILE
	defaultMaxProcesses    = 4096     // RLIMIT_NPROC: per-UID task ceiling on Linux
)

// landlockFSNames, landlockNetNames, and landlockScopeNames give the kernel
// name of each right, indexed by bit position.
var (
	landlockFSNames = []string{
		"EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR",
		"REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK",
		"MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE",
		"IOCTL_DEV", "RESOLVE_UNIX",
	}
	landlockNetNames   = []string{"BIND_TCP", "CONNECT_TCP", "BIND_UDP", "CONNECT_SEND_UDP"}
	landlockScopeNames = []string{"ABSTRACT_UNIX_SOCKET", "SIGNAL"}
)
