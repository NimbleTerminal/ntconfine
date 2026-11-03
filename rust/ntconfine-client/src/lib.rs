// Copyright (c) 2026 Neomantra Corp. Licensed under the MIT License.

//! Minimal zero-dependency Rust client for the `ntconfine-stage` launch contract.
//!
//! Launches a confined worker process via `ntconfine-stage --stage fd:4`, passing
//! the JSON/base64 [`StageSpec`] over file descriptor 4 and an inherited IPC
//! `AF_UNIX` stream socket at file descriptor 3.

use std::ffi::c_int;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// CLI flag passed to `ntconfine-stage` to enter confinement stage mode.
pub const STAGE_ARG: &str = "--stage";

/// Wire-format version for [`StageSpec`].
pub const SPEC_VERSION: u32 = 1;

/// Filesystem, resource, and syscall confinement policy for a worker process.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub exec_paths: Vec<String>,
    pub allow_unsandboxed: bool,
    pub max_address_space: u64,
    pub max_open_files: u64,
    pub max_processes: u64,
}

impl Policy {
    /// Returns the baseline closed confinement policy with platform shared-library
    /// read paths and runtime dynamic loader execution paths.
    pub fn default_policy() -> Self {
        Self {
            read_paths: default_lib_paths(),
            write_paths: Vec::new(),
            exec_paths: default_exec_paths(),
            allow_unsandboxed: false,
            max_address_space: 0,
            max_open_files: 0,
            max_processes: 0,
        }
    }
}

/// Wire payload passed to `ntconfine-stage --stage fd:N`.
#[derive(Clone, Debug)]
pub struct StageSpec {
    pub version: u32,
    pub worker_path: String,
    pub worker_args: Vec<String>,
    pub policy: Policy,
}

impl StageSpec {
    /// Creates a versioned [`StageSpec`] for `worker_path` with `worker_args` and `policy`.
    pub fn new(worker_path: impl Into<String>, worker_args: Vec<String>, policy: Policy) -> Self {
        Self {
            version: SPEC_VERSION,
            worker_path: worker_path.into(),
            worker_args,
            policy,
        }
    }

    /// Serializes this [`StageSpec`] as unpadded URL-safe base64 JSON matching
    /// `pkg/confine.EncodeStageSpec`.
    pub fn encode(&self) -> io::Result<String> {
        if self.worker_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ntconfine: stage spec requires worker_path",
            ));
        }
        let version = if self.version == 0 {
            SPEC_VERSION
        } else {
            self.version
        };
        let mut json = String::with_capacity(256);
        json.push_str("{\"version\":");
        json.push_str(&version.to_string());
        json.push_str(",\"worker_path\":");
        push_json_str(&mut json, &self.worker_path);
        json.push_str(",\"worker_args\":");
        push_json_str_slice(&mut json, &self.worker_args);
        json.push_str(",\"policy\":{\"read_paths\":");
        push_json_str_slice(&mut json, &self.policy.read_paths);
        json.push_str(",\"write_paths\":");
        push_json_str_slice(&mut json, &self.policy.write_paths);
        json.push_str(",\"exec_paths\":");
        push_json_str_slice(&mut json, &self.policy.exec_paths);
        json.push_str(",\"allow_unsandboxed\":");
        json.push_str(if self.policy.allow_unsandboxed {
            "true"
        } else {
            "false"
        });
        json.push_str(",\"max_address_space\":");
        json.push_str(&self.policy.max_address_space.to_string());
        json.push_str(",\"max_open_files\":");
        json.push_str(&self.policy.max_open_files.to_string());
        json.push_str(",\"max_processes\":");
        json.push_str(&self.policy.max_processes.to_string());
        json.push_str("}}");
        Ok(base64_raw_url_encode(json.as_bytes()))
    }
}

/// Returns the standard read-only system library directories for the current OS,
/// matching `ntconfine.DefaultLibPaths`.
pub fn default_lib_paths() -> Vec<String> {
    if cfg!(target_os = "macos") {
        vec![
            "/opt/homebrew/lib".into(),
            "/opt/homebrew/Cellar".into(),
            "/opt/homebrew/opt".into(),
            "/usr/local/lib".into(),
            "/usr/local/Cellar".into(),
            "/usr/local/opt".into(),
            "/usr/lib".into(),
            "/System/Library".into(),
            "/Library/Fonts".into(),
        ]
    } else if cfg!(target_os = "linux") {
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr/lib".into(),
            "/usr/lib64".into(),
            "/usr/local/lib".into(),
            "/etc/ld.so.cache".into(),
            "/etc/fonts".into(),
            "/usr/share/fonts".into(),
            "/usr/local/share/fonts".into(),
            "/var/cache/fontconfig".into(),
        ]
    } else {
        Vec::new()
    }
}

/// Returns the literal dynamic linker paths required for `execve` on Linux.
pub fn default_exec_paths() -> Vec<String> {
    if cfg!(target_os = "linux") {
        vec![
            "/lib64/ld-linux-x86-64.so.2".into(),
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".into(),
            "/usr/lib64/ld-linux-x86-64.so.2".into(),
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".into(),
            "/lib/ld-linux-aarch64.so.1".into(),
            "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1".into(),
            "/usr/lib/ld-linux-aarch64.so.1".into(),
            "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1".into(),
            "/lib/ld-musl-x86_64.so.1".into(),
            "/lib/ld-musl-aarch64.so.1".into(),
        ]
    } else {
        Vec::new()
    }
}

/// Running confined subprocess launched via `ntconfine-stage`.
pub struct Process {
    pub conn: UnixStream,
    child: Child,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    closed: bool,
}

impl Process {
    /// Returns the captured stderr output (up to 64 KiB) from the stage and worker.
    pub fn stderr(&self) -> String {
        let guard = self.stderr_buf.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&guard).into_owned()
    }

    /// Closes the IPC socket, terminates the confined process group, and waits
    /// for the child process to exit.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.conn.shutdown(std::net::Shutdown::Both);
        let pid = self.child.id() as c_int;
        if pid > 0 {
            unsafe {
                let _ = kill(-pid, SIGKILL);
            }
        }
        let _ = self.child.kill();
        let wait_res = self.child.wait();
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
        // Intentional SIGKILL termination of the worker process group is the
        // normal shutdown path; only report an error if reaping the child fails.
        wait_res.map(|_| ())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Launches `stage_path` (`ntconfine-stage`) with `--stage fd:4`, passing `spec`
/// over an inherited pipe at `fd 4` and an `AF_UNIX` stream socket at `fd 3`.
pub fn start_stage(stage_path: impl AsRef<Path>, spec: &StageSpec) -> io::Result<Process> {
    let stage_path = stage_path.as_ref();
    if stage_path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ntconfine: stage_path is required",
        ));
    }
    let meta = std::fs::metadata(stage_path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ntconfine: stage_path is not a regular file",
        ));
    }

    let encoded = spec.encode()?;
    let (parent_sock, child_sock) = UnixStream::pair()?;
    let fork_guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (spec_r, mut spec_w) = os_pipe()?;

    spec_w.write_all(encoded.as_bytes())?;
    spec_w.write_all(b"\n")?;
    drop(spec_w);

    let child_sock_fd = child_sock.as_raw_fd();
    let spec_r_fd = spec_r.as_raw_fd();

    let mut cmd = Command::new(stage_path);
    cmd.arg(STAGE_ARG)
        .arg("fd:4")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    unsafe {
        cmd.pre_exec(move || {
            let _ = setsid();

            // Avoid clobbering spec_r_fd if it happens to be fd 3.
            let mut safe_spec_fd = spec_r_fd;
            if safe_spec_fd == 3 {
                safe_spec_fd = dup(spec_r_fd);
                if safe_spec_fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                if safe_spec_fd == 4 {
                    let next_fd = dup(safe_spec_fd);
                    let _ = close(safe_spec_fd);
                    if next_fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    safe_spec_fd = next_fd;
                }
            }

            if child_sock_fd != 3 {
                if dup2(child_sock_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if fcntl(3, F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            if safe_spec_fd != 4 {
                if dup2(safe_spec_fd, 4) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if fcntl(4, F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            if child_sock_fd > 4 {
                let _ = close(child_sock_fd);
            }
            if safe_spec_fd > 4 {
                let _ = close(safe_spec_fd);
            }
            Ok(())
        });
    }

    let spawn_res = cmd.spawn();
    drop(child_sock);
    drop(spec_r);
    drop(fork_guard);
    let mut child = spawn_res?;

    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_thread = child.stderr.take().map(|mut stderr| {
        let buf = Arc::clone(&stderr_buf);
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut guard = buf.lock().unwrap_or_else(|e| e.into_inner());
                let rem = 65536usize.saturating_sub(guard.len());
                if rem == 0 {
                    continue;
                }
                guard.extend_from_slice(&chunk[..n.min(rem)]);
            }
        })
    });

    Ok(Process {
        conn: parent_sock,
        child,
        stderr_buf,
        stderr_thread,
        closed: false,
    })
}

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
fn os_pipe() -> io::Result<(std::fs::File, std::fs::File)> {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
    if rc == 0 {
        return unsafe {
            let r = std::fs::File::from(OwnedFd::from_raw_fd(fds[0]));
            let w = std::fs::File::from(OwnedFd::from_raw_fd(fds[1]));
            Ok((r, w))
        };
    }
    os_pipe_fallback()
}

#[cfg(not(target_os = "linux"))]
fn os_pipe() -> io::Result<(std::fs::File, std::fs::File)> {
    os_pipe_fallback()
}

fn os_pipe_fallback() -> io::Result<(std::fs::File, std::fs::File)> {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe(fds.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        if fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(fds[1], F_SETFD, FD_CLOEXEC) < 0 {
            let err = io::Error::last_os_error();
            let _ = close(fds[0]);
            let _ = close(fds[1]);
            return Err(err);
        }
        let r = std::fs::File::from(OwnedFd::from_raw_fd(fds[0]));
        let w = std::fs::File::from(OwnedFd::from_raw_fd(fds[1]));
        Ok((r, w))
    }
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_json_str_slice(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(out, item);
    }
    out.push(']');
}

fn base64_raw_url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
#[cfg(target_os = "linux")]
const O_CLOEXEC: c_int = 0o2000000;
const SIGKILL: c_int = 9;

extern "C" {
    fn pipe(fds: *mut c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn dup(oldfd: c_int) -> c_int;
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn setsid() -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
}
