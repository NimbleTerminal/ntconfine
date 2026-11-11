// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// pretendCgoLinked makes this cgo-free test binary answer as a cgo-linked
// program would.
func pretendCgoLinked(t *testing.T) {
	t.Helper()
	real := cgoLinked
	cgoLinked = func() bool { return true }
	t.Cleanup(func() { cgoLinked = real })
}

func TestCgoLinkedIsFalseWithoutCgo(t *testing.T) {
	if cgoLinked() {
		t.Fatal("cgoLinked() = true in a test binary built with CGO_ENABLED=0")
	}
}

// A host that names its own cgo-linked executable as the stage is told why at
// start, instead of finding the worker connection closed later.
func TestSelfStageLinkedWithCgoIsRejectedAtStart(t *testing.T) {
	if !Available() {
		t.Skip("requires Landlock enforcement")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := HelperConfig{WorkerPath: exe, WorkerArgs: []string{probeMarker}, StagePath: exe, Policy: Policy{ExecPaths: []string{exe}}}
	pretendCgoLinked(t)
	if h, err := StartHelper(cfg); !errors.Is(err, ErrCgoStage) {
		if h != nil {
			_ = h.Close()
		}
		t.Fatalf("StartHelper error = %v, want ErrCgoStage", err)
	}
	if cmd, _, err := Command(cfg); !errors.Is(err, ErrCgoStage) || cmd != nil {
		t.Fatalf("Command = %v, %v, want nil, ErrCgoStage", cmd, err)
	}
}

// A separate stage binary is not this program, so the host cannot judge it.
func TestStageIsSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !stageIsSelf(exe) {
		t.Errorf("stageIsSelf(%q) = false for the running executable", exe)
	}
	for _, other := range []string{"/bin/sh", "/nonexistent/ntconfine-stage"} {
		if stageIsSelf(other) {
			t.Errorf("stageIsSelf(%q) = true", other)
		}
	}
}

// The stage refuses before applying anything, so a failed attempt leaves the
// process as it found it.
func TestCgoLinkedStageRefusesBeforeApplyingLimits(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var before, after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	pretendCgoLinked(t)
	if err := RunStagePolicy(Policy{ExecPaths: []string{exe}}, exe, nil); !errors.Is(err, ErrCgoStage) {
		t.Fatalf("RunStagePolicy error = %v, want ErrCgoStage", err)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("RLIMIT_CORE changed from %+v to %+v by a refused stage", before, after)
	}
}
