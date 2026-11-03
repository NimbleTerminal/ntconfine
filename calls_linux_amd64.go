// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

const (
	sysInitModule       = 175
	sysFinitModule      = 313
	sysBPF              = 321
	sysKexecLoad        = 246
	sysKexecFileLoad    = 320
	sysProcessVMReadv   = 310
	sysProcessVMWritev  = 311
	sysSocket           = 41
	sysSeccomp          = 317
	sysKill             = 62
	sysTkill            = 200
	sysTgkill           = 234
	sysRtSigqueueinfo   = 129
	sysRtTgsigqueueinfo = 297
	sysUnshare          = 272
	sysSetns            = 308
	sysPivotRoot        = 155
	sysChroot           = 161
	sysAddKey           = 248
	sysRequestKey       = 249
	sysKeyctl           = 250
	sysUserfaultfd      = 323
	sysPerfEventOpen    = 298
	sysKcmp             = 312
	sysClone            = 56
	sysOpen             = 2
	sysOpenat           = 257
	sysIoctl            = 16
)

// metadataCalls mutate file metadata without opening the file, which Landlock cannot mediate.
var metadataCalls = []uintptr{
	76,          // truncate
	90, 91, 268, // chmod, fchmod, fchmodat
	sysFchmodat2,    //
	92, 93, 94, 260, // chown, fchown, lchown, fchownat
	188, 189, 190, // setxattr, lsetxattr, fsetxattr
	197, 198, 199, // removexattr, lremovexattr, fremovexattr
	132, 235, 261, 280, // utime, utimes, futimesat, utimensat
}
