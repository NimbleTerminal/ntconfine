// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"flag"
	"fmt"
	"math/bits"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

// SECURITY.md states facts that customers rely on. Every checkable fact lives
// in a generated region rendered here from the values the code enforces.
// TestSecurityDocInSync fails when a region is stale; `task security-doc`
// (go test -run TestSecurityDocInSync -update-security-doc) rewrites them.
//
// The macOS profile region can only be rendered on macOS, so it is checked and
// updated there and left untouched elsewhere. CI runs on both.

const securityDocPath = "SECURITY.md"

var updateSecurityDoc = flag.Bool("update-security-doc", false, "rewrite the generated regions of SECURITY.md")

// securityDocRegions lists every generated region, in any order. A nil
// renderer result means the region cannot be rendered on this platform.
var securityDocRegions = map[string]func() *string{
	"limits":        func() *string { return ptr(renderLimits()) },
	"landlock":      func() *string { return ptr(renderLandlock()) },
	"seccomp":       func() *string { return ptr(renderSeccomp()) },
	"macos-profile": renderMacOSProfile,
}

func ptr(s string) *string { return &s }

func regionMarkers(name string) (begin, end string) {
	return "<!-- BEGIN GENERATED:" + name + " (edit the code, then run `task security-doc`) -->",
		"<!-- END GENERATED:" + name + " -->"
}

var (
	regionMarkerRE = regexp.MustCompile(`<!-- (BEGIN|END) GENERATED:([a-z-]+)[^>]*-->`)
	// Facts that belong in a generated region, never in hand-written prose.
	proseHexRE  = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`)
	proseSizeRE = regexp.MustCompile(`\b\d+\s*(KiB|MiB|GiB|bytes)\b`)
)

func TestSecurityDocInSync(t *testing.T) {
	raw, err := os.ReadFile(securityDocPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	for _, m := range regionMarkerRE.FindAllStringSubmatch(doc, -1) {
		if _, known := securityDocRegions[m[2]]; !known {
			t.Errorf("%s has a marker for unknown region %q", securityDocPath, m[2])
		}
	}

	names := make([]string, 0, len(securityDocRegions))
	for name := range securityDocRegions {
		names = append(names, name)
	}
	slices.Sort(names)

	prose := doc
	updated := doc
	stale := false
	for _, name := range names {
		begin, end := regionMarkers(name)
		if strings.Count(doc, begin) != 1 || strings.Count(doc, end) != 1 {
			t.Fatalf("%s must contain exactly one %q ... %q pair", securityDocPath, begin, end)
		}
		bodyOf := func(s string) (pre, body, post string) {
			i := strings.Index(s, begin) + len(begin)
			j := strings.Index(s, end)
			if j < i {
				t.Fatalf("region %q: end marker precedes begin marker", name)
			}
			return s[:i], s[i:j], s[j:]
		}
		pre, _, post := bodyOf(prose)
		prose = pre + post

		want := securityDocRegions[name]()
		if want == nil {
			continue
		}
		pre, got, post := bodyOf(updated)
		wantBody := "\n" + strings.TrimRight(*want, "\n") + "\n"
		if got != wantBody {
			stale = true
			if !*updateSecurityDoc {
				t.Errorf("%s region %q does not match the code; run `task security-doc`.\n--- in file ---%s--- from code ---%s", securityDocPath, name, got, wantBody)
			}
			updated = pre + wantBody + post
		}
	}

	if stale && *updateSecurityDoc {
		if err := os.WriteFile(securityDocPath, []byte(updated), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote generated regions of %s", securityDocPath)
	}

	for _, re := range []*regexp.Regexp{proseHexRE, proseSizeRE} {
		for _, hit := range re.FindAllString(prose, -1) {
			t.Errorf("%s states %q outside a generated region; move the fact into a region rendered from code", securityDocPath, hit)
		}
	}
}

func formatBytes(n uint64) string {
	for _, u := range []struct {
		size uint64
		name string
	}{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= u.size && n%u.size == 0 {
			return fmt.Sprintf("%d %s", n/u.size, u.name)
		}
	}
	return fmt.Sprintf("%d bytes", n)
}

func renderLimits() string {
	var b strings.Builder
	b.WriteString("| Limit | Value | Set by |\n| --- | --- | --- |\n")
	for _, row := range [][3]string{
		{"Paths in each `Policy` list", fmt.Sprint(confine.MaxPolicyPaths), "`confine.MaxPolicyPaths`"},
		{"Total length of all `Policy` paths", formatBytes(confine.MaxPolicyPathBytes), "`confine.MaxPolicyPathBytes`"},
		{"Encoded `StageSpec`", formatBytes(confine.MaxSpecBytes), "`confine.MaxSpecBytes`"},
		{"Captured worker `stderr`", formatBytes(confine.MaxStderrBytes), "`confine.MaxStderrBytes`"},
		{"Linux `RLIMIT_NOFILE` default", fmt.Sprint(defaultMaxOpenFiles), "`Policy.MaxOpenFiles`"},
		{"Linux `RLIMIT_AS` default", formatBytes(defaultMaxAddressSpace), "`Policy.MaxAddressSpace`"},
		{"Linux `RLIMIT_NPROC` default", fmt.Sprint(defaultMaxProcesses), "`Policy.MaxProcesses`"},
	} {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", row[0], row[1], row[2])
	}
	return b.String()
}

// bitNames renders the set bits of mask as backquoted kernel constant names.
func bitNames(prefix string, names []string, mask uint64) string {
	var out []string
	for mask != 0 {
		bit := bits.TrailingZeros64(mask)
		mask &^= 1 << bit
		if bit >= len(names) {
			out = append(out, fmt.Sprintf("`unknown bit %d`", bit))
			continue
		}
		out = append(out, "`"+prefix+names[bit]+"`")
	}
	return strings.Join(out, ", ")
}

func renderLandlock() string {
	const fs, net, scope = "LANDLOCK_ACCESS_FS_", "LANDLOCK_ACCESS_NET_", "LANDLOCK_SCOPE_"
	maxABI := len(fsMaskForABI) - 1
	var b strings.Builder
	fmt.Fprintf(&b, "- **Minimum Landlock ABI:** %d (Linux %s). Older kernels are reported as unavailable.\n", minLandlockABI, minLandlockKernel)
	fmt.Fprintf(&b, "- **Highest Landlock ABI requested:** %d. If a newer kernel rejects the request, the stage retries at ABI %d.\n\n", maxABI, fallbackABI)

	b.WriteString("| Granted on | Rights |\n| --- | --- |\n")
	for _, row := range []struct {
		on   string
		mask uint64
	}{
		{"`Policy.ReadPaths`", accessReadPath},
		{"`Policy.WritePaths`", accessWritePath},
		{"`Policy.ExecPaths` and the worker binary", accessExecPath},
		{"`/dev/null`", accessDevNull},
	} {
		fmt.Fprintf(&b, "| %s | %s |\n", row.on, bitNames(fs, landlockFSNames, row.mask))
	}
	fmt.Fprintf(&b, "\nA path that is a file rather than a directory receives only the rights above that are also in: %s.\n\n", bitNames(fs, landlockFSNames, accessFileMask))

	b.WriteString("Every filesystem right the kernel's ABI supports is handled, so anything not granted above is denied:\n\n")
	b.WriteString("| From ABI | Rights handled |\n| --- | --- |\n")
	var prev uint64
	for abi := 1; abi <= maxABI; abi++ {
		if added := fsMaskForABI[abi] &^ prev; added != 0 {
			fmt.Fprintf(&b, "| %d | %s |\n", abi, bitNames(fs, landlockFSNames, added))
		}
		prev = fsMaskForABI[abi]
	}

	b.WriteString("\nNetwork and IPC rights are handled with no allow rules, so they are denied outright:\n\n")
	b.WriteString("| From ABI | Denied |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| %d | %s |\n", netTCPMinABI, bitNames(net, landlockNetNames, accessNetTCP))
	fmt.Fprintf(&b, "| %d | %s |\n", scopeMinABI, bitNames(scope, landlockScopeNames, scopeAll))
	fmt.Fprintf(&b, "| %d | %s |\n", netUDPMinABI, bitNames(net, landlockNetNames, accessNetAll&^accessNetTCP))
	return b.String()
}

func renderSeccomp() string {
	var b strings.Builder
	arches := make([]string, 0, len(syscallTable))
	for arch := range syscallTable {
		arches = append(arches, arch)
	}
	slices.Sort(arches)
	audit := map[string]uint32{"amd64": auditArchX8664, "arm64": auditArchAArch64}
	var archList []string
	for _, arch := range arches {
		archList = append(archList, fmt.Sprintf("`%s` (`AUDIT_ARCH` `%#x`)", arch, audit[arch]))
	}
	fmt.Fprintf(&b, "- **Architectures:** %s. A syscall from any other architecture, or with a number at or above `%#x` (the x32 ABI), kills the process.\n", strings.Join(archList, ", "), uint32(x32Bit))
	b.WriteString("- **`clone3`** returns `ENOSYS`, so `glibc` falls back to `clone`, whose flags can be inspected.\n")
	fmt.Fprintf(&b, "- **`clone`** returns `EPERM` if any namespace flag in `%#x` (`CLONE_NEW*`) is set; ordinary thread and process creation is allowed.\n", uint32(cloneNewMask))
	fmt.Fprintf(&b, "- **`open`** and **`openat`** return `EPERM` if `O_TRUNC` (`%#x`) is set.\n", uint32(oTruncMask))
	var codes []string
	for _, c := range []struct {
		name string
		code uint32
	}{
		{"FS_IOC_SETFLAGS", ioctlFsSetFlags64},
		{"FS_IOC32_SETFLAGS", ioctlFsSetFlags32},
		{"FS_IOC_FSSETXATTR", ioctlFsSetXattr},
		{"TIOCSTI", ioctlTiocsti},
	} {
		codes = append(codes, fmt.Sprintf("`%s` (`%#x`)", c.name, c.code))
	}
	fmt.Fprintf(&b, "- **`ioctl`** returns `EPERM` for these request codes: %s.\n", strings.Join(codes, ", "))
	b.WriteString("- **`tgkill`** and **`tkill`** return `EPERM` unless their first argument is the worker's own PID.\n")
	b.WriteString("- **Denied with `EPERM`:**\n")
	for _, g := range deniedGroups {
		calls := make([]string, len(g.Calls))
		for i, c := range g.Calls {
			calls[i] = "`" + c + "`"
		}
		fmt.Fprintf(&b, "  - **%s:** %s.\n", g.Title, strings.Join(calls, ", "))
	}
	for _, arch := range arches {
		var absent []string
		for _, g := range deniedGroups {
			for _, c := range g.Calls {
				if slices.Contains(syscallAbsent[arch], c) {
					absent = append(absent, "`"+c+"`")
				}
			}
		}
		if len(absent) > 0 {
			fmt.Fprintf(&b, "- **Not present on `%s`** (the kernel has no such syscall there): %s.\n", arch, strings.Join(absent, ", "))
		}
	}
	return b.String()
}
