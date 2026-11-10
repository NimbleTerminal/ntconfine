// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: MIT

package confine

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
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
	if got := b.String(); got != "hello-world" {
		t.Fatalf("BoundedBuffer.String() = %q, want %q", got, "hello-world")
	}
}

func TestSanitizeTerminalText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain\ttext\nline two", "plain\ttext\nline two"},
		{"a\x1b[1;31mb\x1b[0mc", "abc"},
		{"a\x1b]0;title\x07b", "ab"},
		{"a\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\b", "alinkb"},
		{"a\x1bPpayload\x1b\\b", "ab"},
		{"a\x1b]unterminated\nnext", "a\nnext"},
		{"a\u009b31mb", "ab"},
		{"a\u009d0;t\u009cb", "ab"},
		{"a\x1b(Bb", "ab"},
		{"a\x1bcb", "ab"},
		{"a\x1b", "a"},
		{"a\x1b[", "a"},
		{"safe\u202egnp.exe", "safegnp.exe"},
		{"a\u2066b\u2069c\u200e\u200f\u061c", "abc"},
		{"a\xffb\x7f\x00\rc", "abc"},
		{"caf\u00e9 \u2713", "caf\u00e9 \u2713"},
	} {
		if got := SanitizeTerminalText(tc.in); got != tc.want {
			t.Errorf("SanitizeTerminalText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzSanitizeTerminalText(f *testing.F) {
	f.Add("hello\x1b[31m\x1b]0;t\x07\u202e")
	f.Fuzz(func(t *testing.T, in string) {
		for _, r := range SanitizeTerminalText(in) {
			if r == '\n' || r == '\t' {
				continue
			}
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == utf8.RuneError || isBidiControl(r) {
				t.Fatalf("SanitizeTerminalText(%q) kept %U", in, r)
			}
		}
	})
}

func TestPolicyValidateCapsAndCleanPaths(t *testing.T) {
	for _, bad := range []string{"/a/../etc", "/a/./b", "/a//b", "/a/", "/.."} {
		if err := (Policy{ExecPaths: []string{bad}}).Validate(); err == nil {
			t.Errorf("Validate accepted unclean path %q", bad)
		}
	}
	many := make([]string, MaxPolicyPaths+1)
	for i := range many {
		many[i] = "/r"
	}
	if err := (Policy{ExecPaths: []string{"/w"}, ReadPaths: many}).Validate(); err == nil {
		t.Error("Validate accepted an oversized path list")
	}
	if err := (Policy{ExecPaths: []string{"/w"}, ReadPaths: many[:MaxPolicyPaths]}).Validate(); err != nil {
		t.Errorf("Validate rejected a list at the cap: %v", err)
	}
	long := "/" + strings.Repeat("x", MaxPolicyPathBytes)
	if err := (Policy{ExecPaths: []string{"/w"}, ReadPaths: []string{long}}).Validate(); err == nil {
		t.Error("Validate accepted oversized total path bytes")
	}
}

func TestEncodeStageSpecRejectsOversize(t *testing.T) {
	spec := StageSpec{WorkerPath: "/w", WorkerArgs: []string{strings.Repeat("a", MaxSpecBytes)}}
	if _, err := EncodeStageSpec(spec); err == nil {
		t.Fatal("EncodeStageSpec accepted a spec larger than MaxSpecBytes")
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
