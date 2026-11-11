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
- **Security facts come from code:** Every number, mask, syscall name, Landlock right, and Seatbelt rule in [`SECURITY.md`](SECURITY.md) lives in a `GENERATED` region rendered from the code by `TestSecurityDocInSync`. To change one, change the code and run `task security-doc` (on macOS for the profile region); `task security-doc-check` and `go test` fail when a region is stale. Never restate such a fact in the surrounding prose; point at the region instead.
- **Generated notices:** Run `task notices` (`task notices-check`) whenever dependencies or build targets change.
- **Rust client version follows the release:** When cutting an `ntconfine` release, set `version` in [`rust/ntconfine-client/Cargo.toml`](rust/ntconfine-client/Cargo.toml) to the same major and minor version (`ntconfine v0.2.x` means `ntconfine-client 0.2.y`). The crate may advance its own patch version between `ntconfine` releases when only the Rust client changes.
