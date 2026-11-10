// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

// renderMacOSProfile renders the exact Seatbelt profile HelperPolicy emits for
// a fixed example policy. The example paths do not exist, so the output does
// not depend on the machine: HelperPolicy emits a path it cannot stat as a
// (literal ...) filter, and an existing directory as (subpath ...).
func renderMacOSProfile() *string {
	pol := Policy{
		ReadPaths:  []string{"/opt/ntconfine-example/input"},
		WritePaths: []string{"/opt/ntconfine-example/output"},
		ExecPaths:  []string{"/opt/ntconfine-example/worker"},
	}
	return ptr("```scheme\n" + HelperPolicy(pol) + "```\n")
}
