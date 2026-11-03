# AGENTS.md — ntconfine

## Build and test

Local development uses [`go.work`](go.work) (`use ( . ./pkg/confine )`). Always build and test with `CGO_ENABLED=0`:

```sh
task check
```

Or directly:

```sh
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go -C pkg/confine vet ./...
CGO_ENABLED=0 go test -race -count=1 ./...   # -race on macOS only
CGO_ENABLED=0 go -C pkg/confine test -race -count=1 ./...
CGO_ENABLED=0 GOOS=js GOARCH=wasm go build .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
```

## Rules and invariants

- **Zero external dependencies:** `nimbleterminal.dev/ntconfine`, `nimbleterminal.dev/ntconfine/pkg/confine`, and `cmd/ntconfine-stage` must depend only on the Go standard library (`CGO_ENABLED=0`).
- **Mechanism, not framework:** `ntconfine` launches, restricts, supervises, and terminates OS-confined worker subprocesses. It must never know about application protocols (media, rendering, RPC, etc.).
- **Fail closed:** The zero `Policy` is closed (`AllowUnsandboxed: false`, no readable/writable/executable paths). When OS enforcement is unavailable and `AllowUnsandboxed` is `false`, `StartHelper` and `Command` must return `ErrUnavailable`. When `Available()` is `true`, a missing stage binary is an error, never an unsandboxed fallback.
- **Honest reporting:** `Probe()` and `Helper.Support()` must report only what the OS actually enforces (`landlock+seccomp` on Linux, `sandbox-exec` marked `Deprecated: true` on macOS, `none` elsewhere).
- **Generated notices:** Run `task notices` (`task notices-check`) whenever dependencies or build targets change.
