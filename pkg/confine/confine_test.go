// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

package confine

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeDecodeStageSpec(t *testing.T) {
	spec := StageSpec{
		Policy: Policy{
			ReadPaths:    []string{"/usr/lib", "/tmp/work"},
			ExecPaths:    []string{"/usr/bin/true"},
			MaxProcesses: 4096,
		},
		WorkerPath: "/usr/bin/true",
		WorkerArgs: []string{"--worker", "/tmp/work"},
	}
	if err := spec.Policy.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	enc, err := EncodeStageSpec(spec)
	if err != nil {
		t.Fatalf("EncodeStageSpec: %v", err)
	}
	got, err := DecodeStageSpec(enc)
	if err != nil {
		t.Fatalf("DecodeStageSpec: %v", err)
	}
	if got.Version != SpecVersion || got.WorkerPath != spec.WorkerPath || len(got.WorkerArgs) != 2 {
		t.Fatalf("DecodeStageSpec = %+v, want %+v", got, spec)
	}

	// Unsupported version must fail.
	badVer, err := EncodeStageSpec(StageSpec{
		Version:    99,
		Policy:     spec.Policy,
		WorkerPath: spec.WorkerPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStageSpec(badVer); err == nil {
		t.Fatal("DecodeStageSpec accepted unsupported version 99")
	}
}

func TestBoundedBufferStripsControls(t *testing.T) {
	b := NewBoundedBuffer(32)
	_, _ = b.Write([]byte("hello\x1b[31m-world\x00\n"))
	if got := b.String(); got != "hello[31m-world" {
		t.Fatalf("BoundedBuffer.String() = %q, want %q", got, "hello[31m-world")
	}
}

func FuzzDecodeStageSpec(f *testing.F) {
	seed, _ := EncodeStageSpec(StageSpec{
		Policy:     Policy{ExecPaths: []string{"/bin/echo"}, ReadPaths: []string{"/tmp"}},
		WorkerPath: "/bin/echo",
	})
	f.Add(seed)
	f.Add("")
	f.Add("bad-base64!")

	f.Fuzz(func(t *testing.T, input string) {
		spec, err := DecodeStageSpec(input)
		if err == nil {
			if spec.Version != SpecVersion {
				t.Fatalf("DecodeStageSpec returned Version=%d", spec.Version)
			}
			if err := spec.Policy.Validate(); err == nil {
				for _, p := range strings.Join(append(append(spec.Policy.ReadPaths, spec.Policy.WritePaths...), spec.Policy.ExecPaths...), "") {
					if p < 0x20 || p == 0x7f || (p >= 0x80 && p <= 0x9f) {
						t.Fatalf("Validate accepted control rune %U", p)
					}
				}
				for _, p := range spec.Policy.ExecPaths {
					if !filepath.IsAbs(p) {
						t.Fatalf("Validate accepted non-abs path %q", p)
					}
				}
			}
		}
	})
}
