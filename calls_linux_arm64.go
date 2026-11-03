// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

const (
	sysInitModule       = 105
	sysFinitModule      = 273
	sysBPF              = 280
	sysKexecLoad        = 104
	sysKexecFileLoad    = 294
	sysProcessVMReadv   = 270
	sysProcessVMWritev  = 271
	sysSocket           = 198
	sysSeccomp          = 277
	sysKill             = 129
	sysTkill            = 130
	sysTgkill           = 131
	sysRtSigqueueinfo   = 138
	sysRtTgsigqueueinfo = 240
	sysUnshare          = 97
	sysSetns            = 268
	sysPivotRoot        = 41
	sysChroot           = 51
	sysAddKey           = 217
	sysRequestKey       = 218
	sysKeyctl           = 219
	sysUserfaultfd      = 282
	sysPerfEventOpen    = 241
	sysKcmp             = 272
	sysClone            = 220
	sysOpen             = ^uint32(0)
	sysOpenat           = 56
	sysIoctl            = 29
)

// metadataCalls mutate file metadata without opening the file, which Landlock cannot mediate.
var metadataCalls = []uintptr{
	45,     // truncate
	52, 53, // fchmod, fchmodat
	sysFchmodat2, //
	54, 55,       // fchownat, fchown
	5, 6, 7, // setxattr, lsetxattr, fsetxattr
	14, 15, 16, // removexattr, lremovexattr, fremovexattr
	88, // utimensat
}
