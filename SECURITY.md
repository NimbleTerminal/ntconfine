# Security Policy & Perimeter (`ntconfine`)

This document describes the exact security perimeter of `ntconfine`
(`nimbleterminal.dev/ntconfine`), what it enforces on each operating system,
what lies outside its threat model, and the invariants that human reviewers and
coding agents must preserve.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities in public GitHub issues.
Send reports privately to **`security@neomantra.net`** with a description of the
issue, affected platform/kernel version, and a minimal reproduction.

---

## 1. Threat Model & Trust Boundary

`ntconfine` is designed to **confine a trusted helper executable that processes
untrusted inputs** (such as media containers, PDFs, SVGs, fonts, images, or
untrusted queries).

| In scope (defended against) | Out of scope (requires a VM / container) |
| --- | --- |
| Memory corruption, parser bugs, or logic flaws inside the worker or its native libraries (`libmpv`, `ffmpeg`, PDFium, image/font decoders) | Running **untrusted or adversarial binaries** (`Policy.ExecPaths` must contain trusted local executables) |
| Arbitrary file reads (`$HOME`, `~/.ssh`, `/etc`, credential stores) or directory enumeration outside `Policy.ReadPaths` / `Policy.ExecPaths` | **Kernel exploits** (the worker shares the host OS kernel) |
| File creation, modification, truncation, chmod/chown/xattr/chattr on readable files (unless under `Policy.WritePaths`) | **Speculative execution / CPU side channels** across processes on the same core |
| Outbound or inbound network connections (`socket`, TCP/UDP, Unix domain sockets) | **Hard kernel RSS/VM enforcement on macOS** (Darwin ignores `setrlimit(RLIMIT_AS)`; macOS hosts must enforce per-request deadlines and payload caps in their IPC protocol) |
| Terminal escape injection via `/dev/tty` or raw worker `stderr` | |
| Cross-process signaling (`kill`, `tgkill`, `pidfd_send_signal`) or host FD/memory theft (`pidfd_getfd`, `process_vm_readv`, `ptrace`) | |

---

## 2. Pre-Launch Binary & Policy Verification

Before any process is spawned, `ntconfine` validates both the policy and the
executables:

1. **Closed-by-default `Policy`:** The zero `Policy` grants no readable,
   writable, or executable paths and sets `AllowUnsandboxed: false`.
2. **`Policy.Validate()`:**
   - Rejects empty `ExecPaths` and caps the number of paths in each list and
     the total length of all paths (see **Enforced limits** below).
   - Requires every path in `ReadPaths`, `WritePaths`, and `ExecPaths` to be
     non-empty, valid UTF-8, free of NUL, C0 and C1 control characters, and DEL,
     clean (`filepath.Clean(p) == p`, so no `.` or `..` elements and no repeated
     or trailing separators), and absolute.
   - The same path check applies to `WorkerPath` and the stage binary path, and
     the Rust client's `StageSpec::validate` mirrors it.
3. **`VerifyBinary` & `ResolveSibling`:**
   - `ResolveSibling` resolves a bare binary name strictly inside
     `filepath.Dir(evalSymlinks(os.Executable()))` and **never** searches `$PATH`.
   - `VerifyBinary` resolves symlinks on the binary path and verifies that the
     target is a regular executable file (`mode & 0111 != 0`), is not group- or
     world-writable (`mode & 0022 == 0`), has neither `setuid` nor `setgid` set,
     is owned by the current effective UID or `root` (`uid == 0`), and resides
     in a parent directory that is either not world-writable or has the sticky
     bit (`+t`) set.

---

### Enforced limits

<!-- BEGIN GENERATED:limits (edit the code, then run `task security-doc`) -->
| Limit | Value | Set by |
| --- | --- | --- |
| Paths in each `Policy` list | 128 | `confine.MaxPolicyPaths` |
| Total length of all `Policy` paths | 32 KiB | `confine.MaxPolicyPathBytes` |
| Encoded `StageSpec` | 1 MiB | `confine.MaxSpecBytes` |
| Captured worker `stderr` | 64 KiB | `confine.MaxStderrBytes` |
| Linux `RLIMIT_NOFILE` default | 1024 | `Policy.MaxOpenFiles` |
| Linux `RLIMIT_AS` default | 16 GiB | `Policy.MaxAddressSpace` |
| Linux `RLIMIT_NPROC` default | 4096 | `Policy.MaxProcesses` |
<!-- END GENERATED:limits -->

---

## 3. Linux Confinement Perimeter (`landlock+seccomp`)

On Linux, `ntconfine` launches a small, pure-Go (`CGO_ENABLED=0`) stage process
(`ntconfine-stage` or self-reexec via `--stage fd:<N>`) before `execve`ing the
worker. The minimum kernel is stated under **Landlock rules** below.

### Why a separate stage process is required
Go (especially with CGO/`goffi`) and Rust hosts are already multi-threaded
before spawning a helper. Executing `ntconfine-stage` starts a fresh process
that applies resource limits, Landlock, and `seccomp-bpf` across all of its OS
threads before loading any worker libraries or executing worker code.

### Stage lockdown sequence (`RunStagePolicy`)
1. **No policy paths in `argv`:** The parent passes the base64url-encoded JSON
   `StageSpec` over an inherited anonymous pipe (`--stage fd:<N>`), size-capped
   when encoding and when reading (see **Enforced limits**), and closes the
   descriptor immediately after reading. Nothing sensitive appears in
   `/proc/<pid>/cmdline` or `ps`.
2. **Resource limits (`setrlimit`):** `RLIMIT_CORE` is set to zero, which
   disables core dumps that could leak memory to disk. `RLIMIT_NOFILE`,
   `RLIMIT_AS`, and `RLIMIT_NPROC` take the defaults under **Enforced limits**
   unless the matching `Policy` field is set, and are clamped to the hard limit.
3. **Landlock:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` and `landlock_restrict_self`
   are applied across all OS threads via `syscall.AllThreadsSyscall`. Every
   existing path is canonicalized with `filepath.EvalSymlinks` before its
   `path_beneath` rule is added. On a kernel below the minimum ABI,
   `Probe().Available` is `false`, `Probe().Detail` names the kernel's ABI, and
   `StartHelper`, `Command`, and the stage fail closed with `ErrUnavailable`.
   The exact rights are under **Landlock rules** below.
4. **Seccomp-BPF:** One filter is installed on all threads with
   `SECCOMP_SET_MODE_FILTER` and `SECCOMP_FILTER_TSYNC`. Its exact contents are
   under **Seccomp filter** below. `execve` stays allowed so the stage can
   start the worker; Landlock limits what can be executed. `ftruncate` is not
   denied because it needs a descriptor already open for writing, which
   Landlock only permits under `Policy.WritePaths`.
5. **Irreversible post-`restrict()` failure handling:** Once `landlock_restrict_self`
   succeeds, `RunStagePolicy` never returns to an in-process caller; if
   `seccomp-bpf` or `execve` fails, it writes to `stderr` and calls `os.Exit(1)`.

### Landlock rules

<!-- BEGIN GENERATED:landlock (edit the code, then run `task security-doc`) -->
- **Minimum Landlock ABI:** 3 (Linux 6.2). Older kernels are reported as unavailable.
- **Highest Landlock ABI requested:** 10. If a newer kernel rejects the request, the stage retries at ABI 6.

| Granted on | Rights |
| --- | --- |
| `Policy.ReadPaths` | `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR` |
| `Policy.WritePaths` | `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR`, `LANDLOCK_ACCESS_FS_REMOVE_DIR`, `LANDLOCK_ACCESS_FS_REMOVE_FILE`, `LANDLOCK_ACCESS_FS_MAKE_DIR`, `LANDLOCK_ACCESS_FS_MAKE_REG`, `LANDLOCK_ACCESS_FS_MAKE_SYM`, `LANDLOCK_ACCESS_FS_REFER`, `LANDLOCK_ACCESS_FS_TRUNCATE` |
| `Policy.ExecPaths` and the worker binary | `LANDLOCK_ACCESS_FS_EXECUTE`, `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR` |
| `/dev/null` | `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_TRUNCATE` |

A path that is a file rather than a directory receives only the rights above that are also in: `LANDLOCK_ACCESS_FS_EXECUTE`, `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_TRUNCATE`, `LANDLOCK_ACCESS_FS_IOCTL_DEV`.

Every filesystem right the kernel's ABI supports is handled, so anything not granted above is denied:

| From ABI | Rights handled |
| --- | --- |
| 1 | `LANDLOCK_ACCESS_FS_EXECUTE`, `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR`, `LANDLOCK_ACCESS_FS_REMOVE_DIR`, `LANDLOCK_ACCESS_FS_REMOVE_FILE`, `LANDLOCK_ACCESS_FS_MAKE_CHAR`, `LANDLOCK_ACCESS_FS_MAKE_DIR`, `LANDLOCK_ACCESS_FS_MAKE_REG`, `LANDLOCK_ACCESS_FS_MAKE_SOCK`, `LANDLOCK_ACCESS_FS_MAKE_FIFO`, `LANDLOCK_ACCESS_FS_MAKE_BLOCK`, `LANDLOCK_ACCESS_FS_MAKE_SYM` |
| 2 | `LANDLOCK_ACCESS_FS_REFER` |
| 3 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 5 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| 9 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` |

Network and IPC rights are handled with no allow rules, so they are denied outright:

| From ABI | Denied |
| --- | --- |
| 4 | `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` |
| 6 | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` |
| 10 | `LANDLOCK_ACCESS_NET_BIND_UDP`, `LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP` |
<!-- END GENERATED:landlock -->

### Seccomp filter

<!-- BEGIN GENERATED:seccomp (edit the code, then run `task security-doc`) -->
- **Architectures:** `amd64` (`AUDIT_ARCH` `0xc000003e`), `arm64` (`AUDIT_ARCH` `0xc00000b7`). A syscall from any other architecture, or with a number at or above `0x40000000` (the x32 ABI), kills the process.
- **`clone3`** returns `ENOSYS`, so `glibc` falls back to `clone`, whose flags can be inspected.
- **`clone`** returns `EPERM` if any namespace flag in `0x7e020080` (`CLONE_NEW*`) is set; ordinary thread and process creation is allowed.
- **`open`** and **`openat`** return `EPERM` if `O_TRUNC` (`0x200`) is set.
- **`ioctl`** returns `EPERM` for these request codes: `FS_IOC_SETFLAGS` (`0x40086602`), `FS_IOC32_SETFLAGS` (`0x40046602`), `FS_IOC_FSSETXATTR` (`0x401c5820`), `TIOCSTI` (`0x5412`).
- **`tgkill`** and **`tkill`** return `EPERM` unless their first argument is the worker's own PID.
- **Denied with `EPERM`:**
  - **Network and IPC:** `socket`, `openat2`.
  - **Cross-process signals and FD/memory inspection:** `kill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal`, `pidfd_open`, `pidfd_getfd`, `process_vm_readv`, `process_vm_writev`, `process_madvise`, `ptrace`, `kcmp`.
  - **Namespaces, mounts, and root changes:** `unshare`, `setns`, `mount`, `umount2`, `pivot_root`, `chroot`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`.
  - **Kernel attack surface and keyrings:** `init_module`, `finit_module`, `bpf`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `userfaultfd`, `perf_event_open`, `kexec_load`, `kexec_file_load`, `keyctl`, `add_key`, `request_key`.
  - **Filesystem metadata mutation:** `truncate`, `chmod`, `fchmod`, `fchmodat`, `fchmodat2`, `chown`, `lchown`, `fchown`, `fchownat`, `utime`, `utimes`, `futimesat`, `utimensat`, `setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`.
- **Not present on `arm64`** (the kernel has no such syscall there): `chmod`, `chown`, `lchown`, `utime`, `utimes`, `futimesat`.
<!-- END GENERATED:seccomp -->

---

## 4. macOS Confinement Perimeter (`sandbox-exec`, `Deprecated: true`)

On macOS, `ntconfine` generates a Seatbelt (`(version 1)`) profile via
`HelperPolicy(pol)` and executes `/usr/bin/sandbox-exec -f <profilePath>`:

1. **No policy paths in `argv`:** Both `StartHelper`/`Command` and
   `RunStagePolicy` write the SBPL profile to a `0600` file in `os.TempDir()` and
   pass `-f <profilePath>` (never `-p <sbpl>`), so allowed paths are not exposed
   in `ps` / `sysctl kern.procargs2`.
2. **`dyld-support.sb`, never `system.sb`:** Importing Apple's `system.sb` grants
   high-specificity `allow` rules for `com.apple.cfprefsd.*`, POSIX shared
   memory, `/private/var/run/syslog`, `/usr/share`, `/Library/Preferences`,
   `/private/var/db/timezone`, `/dev/zero`, and `/dev/dtracehelper` that override
   blanket `deny` rules in Seatbelt. `HelperPolicy` imports only `dyld-support.sb`
   and grants `file-map-executable` alongside `file-read*` on `ReadPaths` and
   `ExecPaths`.
3. **Closed metadata (`stat`) on `/Users` and `/private/etc`:** `HelperPolicy`
   does **not** emit a global `(allow file-read-metadata)`. Instead, it grants
   `file-read-metadata` only on exact `literal` ancestor directories of the
   policy's allowed paths (plus `/tmp`, `/var`, and `/private`; `/` itself is
   readable through `dyld-support.sb`). Both `open(2)` and `stat(2)` on `/etc/passwd`,
   `$HOME`, and `~/.ssh` fail with `EPERM`.
4. **Denied capabilities:** Network, Mach lookup and registration, POSIX shared
   memory, writes under `/cores` (core dumps), and the controlling terminal
   `/dev/tty`. The terminal and network denies are emitted after the path
   allows. The exact rules are in the example profile below.
5. **Known OS caveats (`Probe().Deprecated == true`):**
   - Apple marks `/usr/bin/sandbox-exec` as deprecated.
   - The Darwin kernel does not enforce `setrlimit(RLIMIT_AS)`. Hosts on macOS
     must enforce per-request deadlines and payload size bounds in their
     application protocol.

### Example profile

This is the exact profile `HelperPolicy` emits for a policy with one read path
(`/opt/ntconfine-example/input`), one write path (`/opt/ntconfine-example/output`),
and one executable (`/opt/ntconfine-example/worker`). A path that exists and is
a directory is emitted as `(subpath ...)` where this example shows `(literal ...)`.

<!-- BEGIN GENERATED:macos-profile (edit the code, then run `task security-doc`) -->
```scheme
(version 1)
(deny default)
(import "dyld-support.sb")
(allow syscall*)
(allow system-mac-syscall)
(allow mach-bootstrap)
(deny mach-lookup)
(deny mach-register)
(deny ipc-posix-shm*)
(deny file-write* (subpath "/cores"))
(deny file-read* file-test-existence (subpath "/private/etc") (subpath "/etc") (subpath "/Users") (subpath "/private/var/root"))
(allow process-exec (literal "/opt/ntconfine-example/worker"))
(allow signal (target self))
(allow sysctl-read)
(allow file-read* file-test-existence file-map-executable (literal "/opt/ntconfine-example/worker") (literal "/opt/ntconfine-example/input"))
(allow file-read* file-write* file-test-existence (literal "/opt/ntconfine-example/output"))
(allow file-read-metadata file-test-existence (literal "/tmp") (literal "/var") (literal "/private") (literal "/opt/ntconfine-example") (literal "/opt") (literal "/"))
(allow file-read* file-write* file-test-existence (literal "/dev/null"))
(allow file-read* file-test-existence (literal "/dev/urandom") (literal "/dev/random"))
(deny file-read* file-write* (literal "/dev/tty"))
(deny network*)
```
<!-- END GENERATED:macos-profile -->

---

## 5. Descriptor, Environment & Lifecycle Hygiene

- **Atomic `CLOEXEC` creation:** Parent-child sockets and spec pipes use
  `SOCK_CLOEXEC` / `O_CLOEXEC` atomically on Linux and hold `syscall.ForkLock`
  (or `SPAWN_LOCK` in Rust) across descriptor creation and `CloseOnExec` / `spawn`
  on macOS so concurrent child processes never inherit internal descriptors.
- **Non-blocking host socket:** The host end of the worker socketpair is placed
  into non-blocking mode (`syscall.SetNonblock(fd, true)`) before wrapping in
  `os.NewFile`, registering it with Go's netpoller so `SetDeadline` and
  `Close()` can interrupt a blocked `Read` or `Write`.
- **Clean environment & session isolation:** Workers start with an empty
  environment (`Env: []string{}`) and `Setsid: true` (their own process group
  with no controlling terminal).
- **Process-group termination:** `Helper.Close()` and `Process.Close()` close the
  IPC connection, send `SIGKILL` to both `-pid` (the entire process group) and
  `pid`, and reap the child with `Wait()`.
- **Bounded, sanitized `stderr`:** Worker `stderr` is captured into a
  size-capped `BoundedBuffer` (see **Enforced limits**). `Helper.Stderr()`, `Process.Stderr()`, and
  the Rust `Process::stderr()` return it through `SanitizeTerminalText`, which
  removes whole ANSI escape sequences (CSI, OSC, DCS, SOS, PM, APC), all other
  C0/C1 controls except newline and tab, DEL, Unicode bidi marks, embeddings,
  overrides, and isolates, and invalid UTF-8.

---

## 6. Invariant Checklist for Humans and Coding Agents

When modifying `ntconfine`, verify every item below:

- [ ] **Zero external Go dependencies:** `go.mod`, `pkg/confine/go.mod`, and
      `cmd/ntconfine-stage` depend only on the Go standard library (`CGO_ENABLED=0`).
- [ ] **No protocol coupling:** `ntconfine` never imports or defines media,
      rendering, or application wire protocols.
- [ ] **Fail closed:** When `Probe().Available` is `false` and
      `Policy.AllowUnsandboxed` is `false`, `StartHelper` and `Command` must
      return `ErrUnavailable`. When `Probe().Available` is `true`, a missing or
      invalid stage binary must return an error and **never** fall back to
      running unsandboxed.
- [ ] **No `system.sb` or unfiltered `file-read-metadata` on macOS:**
      `TestDarwinHelperPolicyHardening` and `TestDarwinStageDoesNotLeakPolicyPathsInPs`
      must pass on macOS.
- [ ] **Facts come from code:** Every number, mask, syscall name, Landlock
      right, and Seatbelt rule in this file lives in a `GENERATED` region that
      `TestSecurityDocInSync` renders from the code. Change the code, run
      `task security-doc`, and never restate such a fact in the prose.
- [ ] **Preflight gate:** Run `task ci` (and `task test-sandbox-linux` when
      Docker is available) before committing.
