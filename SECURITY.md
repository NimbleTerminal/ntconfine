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
   - Rejects empty `ExecPaths` and caps path list counts (`<= 128` per list) and
     total path bytes (`<= 32768`).
   - Requires every path in `ReadPaths`, `WritePaths`, and `ExecPaths` to be
     non-empty, valid UTF-8, free of NUL and control characters (`< 0x20`,
     `0x7f`, or C1 `0x80`–`0x9f`), clean (`filepath.Clean(p) == p`, so no `.` or
     `..` elements and no repeated or trailing separators), and absolute.
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

## 3. Linux Confinement Perimeter (`landlock+seccomp`)

On Linux (kernel $\ge 6.2$ with Landlock ABI $\ge 3$), `ntconfine` launches a
small, pure-Go (`CGO_ENABLED=0`) stage process (`ntconfine-stage` or self-reexec
via `--stage fd:<N>`) before `execve`ing the worker.

### Why a separate stage process is required
Go (especially with CGO/`goffi`) and Rust hosts are already multi-threaded
before spawning a helper. Executing `ntconfine-stage` starts a fresh process
that applies resource limits, Landlock, and `seccomp-bpf` across all of its OS
threads before loading any worker libraries or executing worker code.

### Stage lockdown sequence (`RunStagePolicy`)
1. **No policy paths in `argv`:** The parent passes the base64url-encoded JSON
   `StageSpec` over an inherited anonymous pipe (`--stage fd:<N>`) capped at
   `1 MiB` (`MaxSpecBytes`, enforced when encoding and when reading), and
   closes the descriptor immediately after reading. Nothing
   sensitive appears in `/proc/<pid>/cmdline` or `ps`.
2. **Resource limits (`setrlimit`):**
   - `RLIMIT_CORE = 0` (disables core dumps that could leak memory to disk).
   - `RLIMIT_NOFILE = 1024` (configurable via `Policy.MaxOpenFiles`, clamped to hard limit).
   - `RLIMIT_AS = 16 GiB` (configurable via `Policy.MaxAddressSpace`, clamped to hard limit).
   - `RLIMIT_NPROC = 4096` (configurable via `Policy.MaxProcesses`, clamped to hard limit).
3. **Landlock (`syscall.AllThreadsSyscall`):**
   - Requires **Landlock ABI $\ge 3$** (Linux 6.2+). On ABI 1–2, which lack
     `LANDLOCK_ACCESS_FS_TRUNCATE`, `Probe().Available` is `false`,
     `Probe().Detail` names the kernel's ABI, and `StartHelper`, `Command`, and
     the stage fail closed with `ErrUnavailable`.
   - Handles filesystem access bits up to ABI 9 (including
     `LANDLOCK_ACCESS_FS_TRUNCATE`, `LANDLOCK_ACCESS_FS_IOCTL_DEV`, and ABI 9's
     `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`), network masks (`LANDLOCK_ACCESS_NET_BIND_TCP`,
     `CONNECT_TCP` at ABI $\ge 4$, plus UDP at ABI $\ge 10$ with automatic
     fallback to ABI 6 if the kernel rejects unknown bits), and IPC scope flags
     (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` at ABI $\ge 6$).
   - Canonicalizes every existing path with `filepath.EvalSymlinks` before
     adding `path_beneath` rules:
     - `ReadPaths`: read-only (`READ_FILE | READ_DIR`).
     - `WritePaths`: read-write (`READ_FILE | READ_DIR | WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | MAKE_SYM | REFER | TRUNCATE`). Creating device nodes, sockets, and FIFOs (`MAKE_CHAR`, `MAKE_BLOCK`, `MAKE_SOCK`, `MAKE_FIFO`) is not granted.
     - `ExecPaths` + `workerPath`: read + execute (`READ_FILE | READ_DIR | EXECUTE`).
     - `/dev/null`: file read-write (`READ_FILE | WRITE_FILE | TRUNCATE`).
   - Enforces `prctl(PR_SET_NO_NEW_PRIVS, 1)` and `landlock_restrict_self` across
     all OS threads via `syscall.AllThreadsSyscall`.
4. **Seccomp-BPF (`SECCOMP_SET_MODE_FILTER` with `SECCOMP_FILTER_TSYNC`):**
   - Verifies `AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64` (killing the process on
     architecture mismatch and rejecting x32 ABI syscalls `>= 0x40000000` on amd64).
   - Returns `ENOSYS` for `clone3` so `glibc` cleanly falls back to `clone(2)`.
   - Inspects `clone(2)` flags (`arg0` on `amd64`/`arm64`) and returns `EPERM` if
     any `CLONE_NEW*` namespace bit (`0x7e020080`) is set, while permitting
     normal thread creation (`CLONE_VM | CLONE_THREAD | ...`).
   - Inspects `tgkill(2)` and `tkill()` and returns `EPERM` unless `tgid == os.Getpid()`
     (for `tgkill`), blocking cross-process thread signaling even on kernels
     without Landlock ABI 6 while letting the Go/C runtime signal its own threads.
   - Inspects `open(2)` (`amd64`) and `openat(2)` (`amd64`/`arm64`) flags and
     returns `EPERM` if `O_TRUNC` (`0x200`) is set.
   - Inspects `ioctl(2)` request codes (`uint32(cmd)`) and returns `EPERM` for
     `FS_IOC_SETFLAGS` (`0x40086602`), `FS_IOC32_SETFLAGS` (`0x40046602`),
     `FS_IOC_FSSETXATTR` (`0x401c5820`), and `TIOCSTI` (`0x00005412`).
   - Denies with `EPERM`:
     - **Network & IPC:** `socket`, `openat2`.
     - **Cross-process signals & FD/memory inspection:** `kill`, `rt_sigqueueinfo`,
       `rt_tgsigqueueinfo`, `pidfd_send_signal`, `pidfd_open`, `pidfd_getfd`,
       `process_vm_readv`, `process_vm_writev`, `process_madvise`, `ptrace`, `kcmp`.
     - **Namespaces, mounts & root changes:** `unshare`, `setns`, `mount`,
       `umount2`, `pivot_root`, `chroot`, `open_tree`, `move_mount`, `fsopen`,
       `fsconfig`, `fsmount`, `fspick`, `mount_setattr`.
     - **Kernel attack surface & keyrings:** `bpf`, `io_uring_setup`,
       `io_uring_enter`, `io_uring_register`, `userfaultfd`, `perf_event_open`,
       `kexec_load`, `kexec_file_load`, `keyctl`, `add_key`, `request_key`.
     - **Filesystem metadata mutation:** `truncate`, `chmod`,
       `fchmod`, `fchmodat`, `fchmodat2`, `chown`, `lchown`, `fchown`,
       `fchownat`, `utime`, `utimes`, `futimesat`, `utimensat`, `setxattr`,
       `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`.
       `ftruncate` is **not** in this list: it needs a descriptor already open
       for writing, which Landlock only permits under `Policy.WritePaths`.
5. **Irreversible post-`restrict()` failure handling:** Once `landlock_restrict_self`
   succeeds, `RunStagePolicy` never returns to an in-process caller; if
   `seccomp-bpf` or `execve` fails, it writes to `stderr` and calls `os.Exit(1)`.

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
4. **Denied capabilities:** Network (`(deny network*)`), Mach lookup/register
   (`(deny mach-lookup)` / `(deny mach-register)`), POSIX shared memory
   (`(deny ipc-posix-shm*)`), core dumps (`(deny file-write* (subpath "/cores"))`),
   and controlling terminal (`(deny file-read* file-write* (literal "/dev/tty"))`,
   emitted after the path allows).
5. **Known OS caveats (`Probe().Deprecated == true`):**
   - Apple marks `/usr/bin/sandbox-exec` as deprecated.
   - The Darwin kernel does not enforce `setrlimit(RLIMIT_AS)`. Hosts on macOS
     must enforce per-request deadlines and payload size bounds in their
     application protocol.

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
- **Bounded, sanitized `stderr`:** Worker `stderr` is captured into a 64 KiB
  `BoundedBuffer` (`MaxStderrBytes`). `Helper.Stderr()`, `Process.Stderr()`, and
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
- [ ] **Preflight gate:** Run `task ci` (and `task test-sandbox-linux` when
      Docker is available) before committing.
