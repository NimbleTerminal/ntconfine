// Copyright (c) 2026 Neomantra Corp. Licensed under the MIT License.

use ntconfine_client::{start_stage, Policy, StageSpec};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--rust-worker-probe" {
        run_worker_probe(&args[2]);
        return;
    }

    println!("running 1 test");
    test_rust_stage_confinement();
    println!("test test_rust_stage_confinement ... ok\n\ntest result: ok. 1 passed; 0 failed");
}

fn run_worker_probe(tmp_dir: &str) {
    let mut conn = unsafe { UnixStream::from(OwnedFd::from_raw_fd(3)) };
    let mut req = [0u8; 4];
    if conn.read_exact(&mut req).is_err() || &req != b"ping" {
        std::process::exit(2);
    }

    let env_empty = std::env::vars_os().next().is_none();
    let allowed_ok = std::fs::read_to_string(PathBuf::from(tmp_dir).join("allowed.txt"))
        .map(|s| s == "hello from rust")
        .unwrap_or(false);
    let passwd_denied = std::fs::read("/etc/passwd").is_err();
    let write_denied = std::fs::write(PathBuf::from(tmp_dir).join("new.txt"), b"x").is_err();
    let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let net_denied = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err();

    let report = format!(
        "env_empty={env_empty} allowed_ok={allowed_ok} passwd_denied={passwd_denied} write_denied={write_denied} net_denied={net_denied}\n"
    );
    let _ = conn.write_all(report.as_bytes());
    let _ = conn.shutdown(std::net::Shutdown::Write);
}

fn test_rust_stage_confinement() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root");
    let stage_bin = std::env::var_os("NTCONFINE_STAGE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("bin").join("ntconfine-stage"));
    if !stage_bin.exists() {
        let status = Command::new("go")
            .current_dir(repo_root)
            .env("CGO_ENABLED", "0")
            .args([
                "build",
                "-o",
                stage_bin.to_str().unwrap(),
                "./cmd/ntconfine-stage",
            ])
            .status()
            .expect("failed to invoke go build for ntconfine-stage");
        assert!(status.success(), "go build ntconfine-stage failed");
    }

    let raw_tmp = std::env::temp_dir().join(format!("ntconfine-rust-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&raw_tmp);
    std::fs::create_dir_all(&raw_tmp).expect("create temp dir");
    let tmp_dir = std::fs::canonicalize(&raw_tmp).expect("canonicalize temp dir");
    let allowed_file = tmp_dir.join("allowed.txt");
    std::fs::write(&allowed_file, b"hello from rust").expect("write allowed.txt");

    let self_exe = std::env::current_exe().expect("current_exe");
    let self_exe = std::fs::canonicalize(&self_exe).unwrap_or(self_exe);

    let mut policy = Policy::default_policy();
    policy
        .read_paths
        .push(tmp_dir.to_string_lossy().into_owned());
    policy
        .exec_paths
        .push(self_exe.to_string_lossy().into_owned());

    let spec = StageSpec::new(
        self_exe.to_string_lossy().into_owned(),
        vec![
            "--rust-worker-probe".into(),
            tmp_dir.to_string_lossy().into_owned(),
        ],
        policy,
    );

    let mut proc = start_stage(&stage_bin, &spec).expect("start_stage");
    if let Err(e) = proc.conn.write_all(b"ping") {
        let _ = proc.close();
        panic!("write ping failed: {e}; stderr={:?}", proc.stderr());
    }

    let mut report = String::new();
    let read_res = proc.conn.read_to_string(&mut report);
    let close_res = proc.close();
    let stderr = proc.stderr();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = read_res {
        panic!("read probe report failed: {e}; close={close_res:?}; stderr={stderr:?}");
    }
    if let Err(e) = close_res {
        panic!("close stage process failed: {e}; stderr={stderr:?}");
    }

    assert!(
        report.contains("env_empty=true"),
        "expected empty env in confined worker, got report={report:?} stderr={stderr:?}"
    );
    assert!(
        report.contains("allowed_ok=true"),
        "expected allowed read to succeed, got report={report:?} stderr={stderr:?}"
    );
    assert!(
        report.contains("passwd_denied=true"),
        "expected /etc/passwd read to be denied, got report={report:?} stderr={stderr:?}"
    );
    assert!(
        report.contains("write_denied=true"),
        "expected write to read-only dir to be denied, got report={report:?} stderr={stderr:?}"
    );
    assert!(
        report.contains("net_denied=true"),
        "expected outbound TCP connect to be denied, got report={report:?} stderr={stderr:?}"
    );
}
