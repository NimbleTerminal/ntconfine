# Usage & Multi-Language Integration Guide (`ntconfine`)

`ntconfine` separates **OS process confinement** from **application IPC**. Once
`ntconfine` (or `ntconfine-stage`) locks down the child process and `execve`s
your worker binary, the host and the worker communicate over a pre-connected
bidirectional stream at **file descriptor `3`** (`fd 3` on Linux and macOS;
`stdin`/`stdout` pipes on Windows).

Both the host and the worker can be written in **any language**. This guide
shows how to integrate `ntconfine` in Go, Rust, C++, and Python.

---

## 1. The Launch Contract

When `ntconfine-stage` is invoked as:

```sh
ntconfine-stage --stage fd:<N>
```

the parent and child agree on four descriptor conventions:

| Descriptor in child | Purpose |
| --- | --- |
| `fd 0`, `fd 1` | `/dev/null` (unless overridden via `Command`) |
| `fd 2` (`stderr`) | Pipe to the parent's 64 KiB control-stripped `BoundedBuffer` |
| `fd 3` | Child end of the `SOCK_STREAM` `socketpair(2)` connected to the host |
| `fd 4 .. 3+k` | Optional `ExtraFiles` passed by the host |
| `fd 4+k` (`fd:<N>`) | Read end of an anonymous `pipe(2)` carrying the base64url-encoded JSON `StageSpec` |

### `StageSpec` JSON wire format

The parent writes the raw URL-safe base64 (`base64url` without `=` padding)
encoding of this JSON object to the spec pipe and closes the write end:

```json
{
  "version": 1,
  "policy": {
    "readPaths": [
      "/usr/lib",
      "/lib",
      "/lib64",
      "/etc/ld.so.cache",
      "/path/to/allowed/input.dat"
    ],
    "writePaths": [],
    "execPaths": [
      "/usr/bin",
      "/bin",
      "/path/to/worker"
    ],
    "allowUnsandboxed": false,
    "maxAddressSpace": 4294967296,
    "maxOpenFiles": 256,
    "maxProcesses": 64
  },
  "workerPath": "/path/to/worker",
  "workerArgs": ["--worker", "input.dat"]
}
```

`ntconfine-stage` reads the token from `fd:<N>`, closes `fd:<N>`, validates the
policy and `workerPath`, applies OS confinement, and `execve`s `workerPath` with
`fd 3` intact.

---

## 2. Go (`nimbleterminal.dev/ntconfine`)

### Single-binary or sibling-worker pattern

In Go, your binary can either launch a separate worker binary + `ntconfine-stage`
beside itself, or re-execute itself for both roles (`StagePath: exe`,
`WorkerPath: exe`):

```go
package main

import (
	"bufio"
	"fmt"
	"os"

	"nimbleterminal.dev/ntconfine"
)

func main() {
	// 1. Stage role (Linux): apply Landlock + rlimits + seccomp-bpf, then execve the worker.
	if len(os.Args) == 3 && os.Args[1] == ntconfine.StageArg {
		if err := ntconfine.RunStage(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
	}

	// 2. Worker role: runs inside the sandbox and speaks over fd 3.
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		conn := ntconfine.WorkerConn()
		defer conn.Close()
		_, _ = fmt.Fprintln(conn, "pong")
		return
	}

	// 3. Host role: probe support, build a policy, and start the confined worker.
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	pol := ntconfine.DefaultPolicy(exe, "/path/to/allowed/dir")

	helper, err := ntconfine.StartHelper(ntconfine.HelperConfig{
		Policy:     pol,
		WorkerPath: exe,
		WorkerArgs: []string{"--worker"},
		StagePath:  exe, // omit when shipping cmd/ntconfine-stage next to the host binary
	})
	if err != nil {
		panic(err)
	}
	defer helper.Close()

	reply, err := bufio.NewReader(helper.Conn).ReadString('\n')
	if err != nil {
		panic(fmt.Sprintf("worker failed (%v): %s", err, helper.Stderr()))
	}
	fmt.Printf("mechanism=%s enforced=%v reply=%s",
		helper.Support().Mechanism, helper.Enforced(), reply)
}
```

> **When to ship the standalone `ntconfine-stage` binary:** If your Go host links
> CGO or `goffi` (or spawns background threads during `init`), build
> `./cmd/ntconfine-stage` with `CGO_ENABLED=0` and place it beside your host
> binary. Leave `HelperConfig.StagePath` empty and `StartHelper` will resolve it
> automatically via `ResolveSibling("ntconfine-stage")`.

### Passing extra file descriptors (`ExtraFiles`)

Any `*os.File` entries in `HelperConfig.ExtraFiles` are inherited by the worker
starting at **`fd 4`** (`fd 3` is always the `Helper.Conn` socketpair).

---

## 3. Standalone Go Stage Client (`nimbleterminal.dev/ntconfine/pkg/confine`)

If your Go application only needs to drive an installed `ntconfine-stage` binary
(or wants to depend only on the MIT-licensed client package without linking the
root enforcement package), import `nimbleterminal.dev/ntconfine/pkg/confine`:

```go
package main

import (
	"bufio"
	"fmt"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

func run(stageBin, workerBin, inputDir string) error {
	spec := confine.StageSpec{
		Version: confine.SpecVersion,
		Policy: confine.Policy{
			ReadPaths: []string{"/usr/lib", "/lib", "/lib64", "/System/Library", inputDir},
			ExecPaths: []string{"/usr/bin", "/bin", workerBin},
		},
		WorkerPath: workerBin,
		WorkerArgs: []string{"--serve"},
	}

	proc, err := confine.StartStage(stageBin, nil, spec)
	if err != nil {
		return err
	}
	defer proc.Close()

	line, err := bufio.NewReader(proc.Conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read failed (%w): %s", err, proc.Stderr())
	}
	fmt.Print(line)
	return nil
}
```

---

## 4. Rust Stage Client (`rust/ntconfine-client`)

Add `ntconfine-client` (`rust/ntconfine-client`, MIT-licensed, zero external
crate dependencies) to your workspace and invoke `Process::start`:

```rust
use ntconfine_client::{Policy, Process, StageSpec};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stage_bin = Path::new("/usr/local/bin/ntconfine-stage");
    let worker_bin = "/usr/local/bin/my-rust-worker";

    let policy = Policy::default_for_worker(worker_bin, &["/var/lib/myapp/inputs"]);
    let spec = StageSpec::new(policy, worker_bin, vec!["--worker".to_string()]);

    let mut proc = Process::start(stage_bin, &[], &spec)?;
    proc.stream().write_all(b"ping\n")?;

    let mut reader = BufReader::new(proc.stream().try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    println!("worker replied: {line}");

    proc.close()?;
    Ok(())
}
```

Inside the Rust worker binary, wrap `fd 3` with `FromRawFd`:

```rust
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

fn worker_conn() -> UnixStream {
    // SAFETY: ntconfine attaches the worker end of the socketpair at fd 3.
    unsafe { UnixStream::from_raw_fd(3) }
}
```

---

## 5. C++ Host & Worker Integration

Neither a C++ worker nor a C++ host needs an external library — POSIX
`<sys/socket.h>` and `<unistd.h>` are sufficient.

### C++ Worker (launched by Go, Rust, or C++)

Inside a confined C++ worker, `fd 3` is already open and connected to the host:

```cpp
// worker.cpp — compile with: c++ -O2 -std=c++20 worker.cpp -o my-cpp-worker
#include <cstdio>
#include <cstring>
#include <unistd.h>

static constexpr int kWorkerFD = 3;

int main() {
    char buf[256];
    ssize_t n = ::read(kWorkerFD, buf, sizeof(buf) - 1);
    if (n <= 0) {
        return 1;
    }
    buf[n] = '\0';

    const char* reply = "hello from confined C++ worker\n";
    if (::write(kWorkerFD, reply, std::strlen(reply)) < 0) {
        return 1;
    }
    ::close(kWorkerFD);
    return 0;
}
```

### C++ Host driving `ntconfine-stage`

A C++ host creates a `socketpair` (child end mapped to `fd 3`) and a `pipe`
(read end mapped to `fd 4`), forks and execs `ntconfine-stage --stage fd:4`, and
writes the base64url-encoded `StageSpec` JSON to the pipe:

```cpp
// host.cpp — minimal POSIX launcher for ntconfine-stage
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <string>

struct ConfinedChild {
    pid_t pid = -1;
    int conn_fd = -1;
};

ConfinedChild start_confined(const char* stage_path, const std::string& spec_b64url) {
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return {};
    ::fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(sv[1], F_SETFD, FD_CLOEXEC);

    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        ::close(sv[0]); ::close(sv[1]);
        return {};
    }
    ::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = ::fork();
    if (pid == 0) {
        ::setsid();
        ::close(sv[0]);
        ::close(pipefd[1]);
        // Map worker socket to fd 3 and spec pipe read end to fd 4 (clearing FD_CLOEXEC).
        if (::dup2(sv[1], 3) < 0 || ::dup2(pipefd[0], 4) < 0) _exit(127);
        if (sv[1] > 4) ::close(sv[1]);
        if (pipefd[0] > 4) ::close(pipefd[0]);

        char* const argv[] = {
            const_cast<char*>(stage_path),
            const_cast<char*>("--stage"),
            const_cast<char*>("fd:4"),
            nullptr
        };
        char* const envp[] = {nullptr};
        ::execve(stage_path, argv, envp);
        _exit(127);
    }

    ::close(sv[1]);
    ::close(pipefd[0]);
    (void)::write(pipefd[1], spec_b64url.data(), spec_b64url.size());
    ::close(pipefd[1]);
    return {pid, sv[0]};
}
```

---

## 6. Python Host & Worker Integration

Python's standard library (`socket`, `os`, `subprocess`, `json`, `base64`) can
both drive `ntconfine-stage` as a host and run inside the sandbox as a worker.

> **Important policy note for Python workers:** Because `python3` is a
> dynamically linked interpreter that reads its standard library and
> `site-packages` at startup, `Policy.ExecPaths` must include the resolved
> `python3` binary (or its parent directory) and `Policy.ReadPaths` must include
> your Python installation prefix (`sys.base_prefix`, `sys.prefix`, and any
> virtual-environment `site-packages` directory).

### Python Worker (`worker.py`)

```python
#!/usr/bin/env python3
import socket
import sys

def main() -> None:
    # fd 3 is the socketpair inherited from ntconfine-stage.
    with socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        data = conn.recv(1024)
        conn.sendall(b"confined-python-ack:" + data)

if __name__ == "__main__":
    main()
```

### Python Host driving `ntconfine-stage`

```python
import base64
import json
import os
import socket
import subprocess
import sys

def start_stage(stage_bin: str, worker_script: str, read_paths: list[str]):
    python_bin = os.path.realpath(sys.executable)
    worker_script = os.path.realpath(worker_script)

    spec = {
        "version": 1,
        "policy": {
            "readPaths": [
                "/usr/lib", "/lib", "/lib64",
                "/System/Library", "/Library/Frameworks",
                "/opt/homebrew", "/usr/local",
                os.path.realpath(sys.base_prefix),
                os.path.realpath(sys.prefix),
                worker_script,
                *read_paths,
            ],
            "execPaths": [
                "/usr/bin", "/bin",
                os.path.dirname(python_bin),
                python_bin,
            ],
        },
        "workerPath": python_bin,
        "workerArgs": ["-I", "-B", worker_script],  # -I isolated mode, -B no .pyc writes
    }
    spec_b64 = base64.urlsafe_b64encode(json.dumps(spec).encode()).rstrip(b"=")

    host_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pr, pw = os.pipe()

    try:
        # Map child_sock -> fd 3 and pr -> fd 4 in the child before exec:
        def preexec():
            os.dup2(child_sock.fileno(), 3)
            os.dup2(pr, 4)

        proc = subprocess.Popen(
            [stage_bin, "--stage", "fd:4"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={},
            start_new_session=True,
            pass_fds=(3, 4),
            preexec_fn=preexec,
        )
    finally:
        child_sock.close()
        os.close(pr)

    os.write(pw, spec_b64)
    os.close(pw)
    return proc, host_sock
```
