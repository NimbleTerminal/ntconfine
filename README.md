# ntconfine — OS subprocess confinement for Nimble Terminal

<p>
    <a href="https://github.com/NimbleTerminal/ntconfine/tags"><img src="https://img.shields.io/github/tag/NimbleTerminal/ntconfine.svg" alt="Latest Release"></a>
    <a href="https://pkg.go.dev/nimbleterminal.dev/ntconfine"><img src="https://pkg.go.dev/badge/nimbleterminal.dev/ntconfine.svg" alt="Go Reference"></a>
    <a href="https://github.com/NimbleTerminal/ntconfine/actions/workflows/ci.yml"><img src="https://github.com/NimbleTerminal/ntconfine/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="./CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg" alt="Code Of Conduct"></a>
</p>

`ntconfine` (`nimbleterminal.dev/ntconfine`) launches a helper executable inside an
OS sandbox under a closed-by-default policy, hands you a socketpair connection to
it, and gets out of the way.

It is the OS-confinement foundation underneath
[`ntmediabox`](https://github.com/NimbleTerminal/ntmediabox) and the rest of the
Nimble Terminal stack, giving applications a narrow, dependency-free way to run
risky media and document parsers (`libmpv`, `ffmpeg`, PDF, SVG, font, and image
decoders) in a separate process that cannot read `$HOME` or `/etc`, open network
sockets, touch the controlling terminal, or signal the host. While `ntmediabox`
layers bounds-checked media and rendering protocols on top, `ntconfine` knows
nothing about media or frames: it confines the process, wires up `fd 3` (or
pipes on Windows) and a bounded stderr buffer, and leaves the wire protocol to
you.

Both the host and the confined worker can be written in **any language**:
`ntconfine-stage` takes a language-neutral JSON `StageSpec` over an inherited
pipe descriptor (`--stage fd:<N>`), locks down the OS process, and `execve`s the
target binary with its IPC socket on `fd 3`.

| Component | Language | License | What it provides |
| --- | --- | --- | --- |
| [`nimbleterminal.dev/ntconfine`](.) & [`cmd/ntconfine-stage`](./cmd/ntconfine-stage) | Go (`CGO_ENABLED=0`) | Dual (`AGPL-3.0-only` w/ Linking Exception or Commercial) | Full sandbox enforcement engine (`StartHelper`, `Command`, `RunStage`, `Probe`) and the standalone `ntconfine-stage` binary |
| [`nimbleterminal.dev/ntconfine/pkg/confine`](./pkg/confine) | Go (`CGO_ENABLED=0`) | [MIT](./pkg/confine/LICENSE) | Standalone Go client (`StartStage`, `Policy`, `StageSpec`) that drives an external `ntconfine-stage` binary without linking AGPL code |
| [`rust/ntconfine-client`](./rust/ntconfine-client) | Rust | [MIT](./rust/ntconfine-client/LICENSE) | Rust client crate (`Process::start`, `Policy`, `StageSpec`) that drives the same `ntconfine-stage` binary |

- **[Usage & Multi-Language Integration Guide (`USAGE.md`)](./USAGE.md):** Complete integration examples for **Go**, **Rust**, **C++**, and **Python** hosts and workers, plus the `--stage fd:<N>` launch contract.
- **[Security Policy & Perimeter (`SECURITY.md`)](./SECURITY.md):** Detailed breakdown of the Linux (`landlock+seccomp`) and macOS (`sandbox-exec`) perimeters, threat model, and review checklist for humans and coding agents.

## Install

Requires Go 1.26 or later (`CGO_ENABLED=0`; zero external Go dependencies).

```sh
# Full enforcement library + stage launcher
go get nimbleterminal.dev/ntconfine@latest

# Or the standalone stage client package
go get nimbleterminal.dev/ntconfine/pkg/confine@latest

# Build the standalone ntconfine-stage binary (used by CGO, Rust, C++, or Python hosts)
CGO_ENABLED=0 go build -o bin/ntconfine-stage ./cmd/ntconfine-stage
```

## Binary releases

Tagged `v*` releases publish `ntconfine-stage` archives for Linux and macOS
(`amd64` and `arm64`), with SHA-256 checksums, usage documentation, and licenses.
The macOS binaries are Developer ID signed and notarized. Windows remains a
library cross-build target; there is no supported Windows confinement stage.

The release workflow uses GoReleaser v2 (Pro is not required) and the checked-in
`go.work` so both Go modules are built from the same commit. It requires the same
GitHub secrets as gloss: `MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`,
`MACOS_NOTARY_KEY`, `MACOS_NOTARY_KEY_ID`, and `MACOS_NOTARY_ISSUER_ID`.
Signing or notarization failures stop publication.

Run `task release-check` to validate the configuration and `task release` to
package an unsigned snapshot in `dist/` without publishing or using Apple
credentials. Pull requests changing release configuration also build snapshots.
Push a root-module `v*` tag to publish; `pkg/confine/v*` tags do not trigger
binary releases.

## Quickstart

```go
package main

import (
	"bufio"
	"fmt"
	"os"

	"nimbleterminal.dev/ntconfine"
)

func main() {
	// 1. Stage role (Linux): lock down all OS threads and execve the worker.
	if len(os.Args) == 3 && os.Args[1] == ntconfine.StageArg {
		if err := ntconfine.RunStage(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
	}

	// 2. Worker role: runs inside the sandbox and speaks over WorkerConn() (fd 3).
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		conn := ntconfine.WorkerConn()
		defer conn.Close()
		_, _ = fmt.Fprintln(conn, "hello from inside the sandbox")
		return
	}

	// 3. Host role: build a closed-by-default policy and start the confined worker.
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	helper, err := ntconfine.StartHelper(ntconfine.HelperConfig{
		Policy:     ntconfine.DefaultPolicy(exe, "/path/to/allowed/input.dat"),
		WorkerPath: exe,
		WorkerArgs: []string{"--worker"},
		StagePath:  exe, // or omit to use a sibling ntconfine-stage binary
	})
	if err != nil {
		panic(err)
	}
	defer helper.Close()

	line, _ := bufio.NewReader(helper.Conn).ReadString('\n')
	fmt.Printf("worker (%s): %s", helper.Support().Mechanism, line)
}
```

See [`USAGE.md`](./USAGE.md) for the standalone Go stage client (`pkg/confine`),
Rust client (`ntconfine-client`), and C++ / Python host and worker examples.

## Platform overview

| Platform | `Probe().Mechanism` | Enforcement summary |
| --- | --- | --- |
| **Linux** (kernel $\ge$ 5.13) | `landlock+seccomp` | Landlock (ABI v3–v10), `rlimits` (`CORE=0`, `NOFILE`, `AS`, `NPROC`), and `seccomp-bpf` (`SECCOMP_FILTER_TSYNC`) applied across all OS threads before `execve` |
| **macOS** | `sandbox-exec` (`Deprecated: true`) | Seatbelt profile (`dyld-support.sb`) written to a `0600` temp file denying network, Mach lookup/register, POSIX SHM, `/Users`, `/private/etc` (both data and `stat` metadata), `/dev/tty`, and file writes |
| **Windows / other** | `none` | `Probe().Available == false`. Fails closed with `ErrUnavailable` unless `Policy.AllowUnsandboxed` is explicitly `true` |

See [`SECURITY.md`](./SECURITY.md) for the full syscall filter, Seatbelt rules,
and threat model.

## Validation

Install [Task](https://taskfile.dev/), then run the full preflight:

```sh
task ci                 # full preflight: fmt-check, whitespace-check, lint, check, build, fuzz
task check              # vet, race tests (root + pkg/confine), Rust client tests, wasm/windows/linux cross-builds, notices check
task lint               # golangci-lint across darwin, linux, windows, and pkg/confine
task fuzz               # fuzz Policy.Validate and StageSpec decoding
task test-sandbox-linux # run the Linux Landlock + seccomp suite in Docker from macOS
```

Repository invariants and build rules are documented in [AGENTS.md](./AGENTS.md).

## Open Collaboration

Contributions and feedback are welcome. Please follow our
[Code of Conduct](./CODE_OF_CONDUCT.md), and report security issues privately as
described in [SECURITY.md](./SECURITY.md).

- [Report an issue](https://github.com/NimbleTerminal/ntconfine/issues)
- [Submit a pull request](https://github.com/NimbleTerminal/ntconfine/pulls)

## License

Copyright (c) 2026 [Neomantra Corp](https://www.neomantra.com). All rights reserved.

`ntconfine` is dual-licensed (`AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial`), with the launch contract and external stage clients in [`pkg/confine`](./pkg/confine) and [`rust/ntconfine-client`](./rust/ntconfine-client) available under the [MIT License](./pkg/confine/LICENSE):

1. **Open-Source & Local CLI/Desktop Use:** Licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)** with the **NimbleTerminal Open-Source Linking Exception (AGPLv3 Section 7)** in [`LICENSE`](./LICENSE), allowing open-source modules from the `NimbleTerminal`, `NimbleMarkets`, and `wethinkt` organizations (including `ntmediabox`, `ntbrowser`, `ntvideo`, `ntpicture`, `ntpdf`, `ntsvg`, `nttypeset`, `gloss`, and `go-thinkt`) to import and link `ntconfine` directly for local CLI and desktop execution under their respective licenses.
2. **Cloud, Hosted Sandbox & Closed-Source OEM Use:** Deploying, hosting, streaming, or executing modified versions of `ntconfine` (or covered works linking it) inside a commercial hosted service, remote terminal/multiplexer service, cloud AI agent sandbox, multi-tenant server, or closed-source commercial product requires either full **AGPLv3 Section 13** Corresponding Source disclosure of the covered work or a **Commercial OEM & Enterprise License from Neomantra Corp.** (see [`LICENSE-COMMERCIAL.md`](./LICENSE-COMMERCIAL.md) or contact `licensing@nimbleterminal.com`).

Dependency notices are listed in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

----
Made with :heart: and :fire: by the team behind [Nimble Terminal](https://nimbleterminal.dev).
