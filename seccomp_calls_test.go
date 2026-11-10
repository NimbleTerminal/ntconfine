// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"slices"
	"testing"
)

var seccompArches = map[string]uint32{"amd64": auditArchX8664, "arm64": auditArchAArch64}

// TestStageSeccompProgramDeniesEveryListedSyscall runs the real stage filter
// for both architectures through the BPF simulator.
func TestStageSeccompProgramDeniesEveryListedSyscall(t *testing.T) {
	const selfPID = 4242
	for goarch, audit := range seccompArches {
		prog, err := buildSeccompProgram(goarch, audit, selfPID)
		if err != nil {
			t.Fatalf("%s: %v", goarch, err)
		}
		if len(prog) > 4096 {
			t.Fatalf("%s: program has %d instructions (BPF_MAXINSNS is 4096)", goarch, len(prog))
		}
		for _, g := range deniedGroups {
			for _, name := range g.Calls {
				nr, ok, err := syscallNR(goarch, name)
				if err != nil {
					t.Fatalf("%s: %v", goarch, err)
				}
				if !ok {
					continue
				}
				if got := evalSeccompBPF(t, prog, uint32(nr), audit, 0, 0, 0, 0); got != seccompRetErrno|linuxEPERM {
					t.Errorf("%s: %s (%d) = %#x, want EPERM", goarch, name, nr, got)
				}
			}
		}
		clone3, _, _ := syscallNR(goarch, "clone3")
		if got := evalSeccompBPF(t, prog, uint32(clone3), audit, 0, 0, 0, 0); got != seccompRetErrno|linuxENOSYS {
			t.Errorf("%s: clone3 = %#x, want ENOSYS", goarch, got)
		}
		// read(2) is 0 on amd64 and 63 on arm64; neither may be denied.
		for _, nr := range []uint32{0, 63} {
			denied, _ := deniedSyscalls(goarch)
			if slices.Contains(denied, uintptr(nr)) {
				continue
			}
			if got := evalSeccompBPF(t, prog, nr, audit, 0, 0, 0, 0); got != seccompRetAllow {
				t.Errorf("%s: syscall %d = %#x, want allow", goarch, nr, got)
			}
		}
	}
}

func TestDeniedGroupsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range deniedGroups {
		if g.Title == "" || len(g.Calls) == 0 {
			t.Errorf("empty denied group %+v", g)
		}
		for _, name := range g.Calls {
			if seen[name] {
				t.Errorf("syscall %q is listed twice", name)
			}
			seen[name] = true
			if name == "clone3" || name == "execve" {
				t.Errorf("%s must not be denied with EPERM", name)
			}
		}
	}
	for goarch, table := range syscallTable {
		byNR := map[uintptr]string{}
		for name, nr := range table {
			if other, dup := byNR[nr]; dup {
				t.Errorf("%s: %s and %s share number %d", goarch, name, other, nr)
			}
			byNR[nr] = name
			if slices.Contains(syscallAbsent[goarch], name) {
				t.Errorf("%s: %s is both numbered and marked absent", goarch, name)
			}
		}
		if _, _, err := syscallNR(goarch, "no_such_call"); err == nil {
			t.Errorf("%s: unknown syscall name must be an error", goarch)
		}
	}
	if _, err := deniedSyscalls("riscv64"); err == nil {
		t.Error("an architecture without a table must be an error")
	}
}
