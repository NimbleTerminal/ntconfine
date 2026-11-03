// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

// Command ntconfine-stage is the pure-Go (CGO_ENABLED=0) helper stage binary
// used to apply Landlock, rlimits, and seccomp-bpf across all OS threads on
// Linux (or /usr/bin/sandbox-exec on macOS) before execve'ing a worker binary.
package main

import (
	"fmt"
	"os"

	"nimbleterminal.dev/ntconfine"
)

func main() {
	if err := ntconfine.RunStage(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(9)
	}
}
