// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

//go:build darwin

package ntconfine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nimbleterminal.dev/ntconfine/pkg/confine"
)

func TestDarwinHelperPolicyHardening(t *testing.T) {
	missingFile := "/tmp/ntconfine-missing-media-file-998877.mp4"
	pol := DefaultPolicy("/usr/bin/true", missingFile)
	sbpl := HelperPolicy(pol)

	if strings.Contains(sbpl, "(import \"system.sb\")") {
		t.Fatalf("HelperPolicy must not import system.sb (leaks mach-lookup, shm, syslog, /usr/share):\n%s", sbpl)
	}
	for _, mustContain := range []string{
		"(import \"dyld-support.sb\")",
		"(deny mach-lookup)",
		"(deny mach-register)",
		"(deny ipc-posix-shm*)",
		"(deny file-write* (subpath \"/cores\"))",
		"(deny file-read* file-write* (literal \"/dev/tty\"))",
		"(deny file-read* file-test-existence (subpath \"/private/etc\") (subpath \"/etc\") (subpath \"/Users\") (subpath \"/private/var/root\"))",
	} {
		if !strings.Contains(sbpl, mustContain) {
			t.Errorf("HelperPolicy missing %q in:\n%s", mustContain, sbpl)
		}
	}

	if strings.Contains(sbpl, "(allow file-read-metadata)") {
		t.Fatalf("HelperPolicy contains unscoped (allow file-read-metadata):\n%s", sbpl)
	}
	if strings.Contains(sbpl, "(subpath \"/tmp/ntconfine-missing-media-file-998877.mp4\")") ||
		strings.Contains(sbpl, "(subpath \"/private/tmp/ntconfine-missing-media-file-998877.mp4\")") {
		t.Fatalf("HelperPolicy turned missing file into subpath grant:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "(literal \"/tmp/ntconfine-missing-media-file-998877.mp4\")") &&
		!strings.Contains(sbpl, "(literal \"/private/tmp/ntconfine-missing-media-file-998877.mp4\")") {
		t.Fatalf("HelperPolicy did not emit literal rule for missing file:\n%s", sbpl)
	}

	if !Available() {
		t.Skip("sandbox-exec unavailable")
	}

	for _, forbidden := range []string{
		"/etc/passwd",
		"/private/etc/passwd",
		"/usr/share/man/man1/ls.1",
		"/Library/Preferences/Logging",
		"/private/var/db/timezone",
	} {
		cmd, _, err := Command(HelperConfig{
			Policy:     DefaultPolicy("/bin/cat"),
			WorkerPath: "/bin/cat",
			WorkerArgs: []string{forbidden},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Run(); err == nil {
			t.Fatalf("reading %q succeeded under HelperPolicy", forbidden)
		}
	}

	for _, forbiddenStat := range []string{"/etc/passwd", "/private/etc/passwd"} {
		cmd, _, err := Command(HelperConfig{
			Policy:     DefaultPolicy("/usr/bin/stat"),
			WorkerPath: "/usr/bin/stat",
			WorkerArgs: []string{forbiddenStat},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Run(); err == nil {
			t.Fatalf("stat(%q) succeeded under HelperPolicy", forbiddenStat)
		}
	}

	// Build a native Darwin probe to verify Mach bootstrap_look_up, POSIX
	// shm_open, unixgram connect to /private/var/run/syslog, /usr/share,
	// /Library/Preferences/Logging, /private/var/db/timezone, /dev/zero, and
	// /dev/dtracehelper are all denied under HelperPolicy(DefaultPolicy(...)).
	if _, err := os.Stat("/usr/bin/cc"); err == nil {
		rawDir := t.TempDir()
		probeDir, err := filepath.EvalSymlinks(rawDir)
		if err != nil {
			t.Fatal(err)
		}
		cFile := filepath.Join(probeDir, "darwin_probe.c")
		binFile := filepath.Join(probeDir, "darwin_probe")
		cSrc := `#include <servers/bootstrap.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    mach_port_t p = MACH_PORT_NULL;
    kern_return_t kr_cfprefs = bootstrap_look_up(bootstrap_port, "com.apple.cfprefsd.agent", &p);
    kern_return_t kr_unlisted = bootstrap_look_up(bootstrap_port, "com.apple.unlisted.service", &p);
    int shm = shm_open("apple.shm.notification_center", O_RDONLY, 0);

    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    int syslog_rc = -1;
    if (s >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/private/var/run/syslog", sizeof(addr.sun_path) - 1);
        syslog_rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        close(s);
    }

    int fd_man = open("/usr/share/man/man1/ls.1", O_RDONLY);
    int fd_log = open("/Library/Preferences/Logging", O_RDONLY);
    int fd_tz = open("/private/var/db/timezone", O_RDONLY);
    int fd_zero = open("/dev/zero", O_RDWR);
    int fd_dtrace = open("/dev/dtracehelper", O_RDWR);

    printf("cfprefs=%d unlisted=%d shm=%d syslog=%d man=%d log=%d tz=%d zero=%d dtrace=%d\n",
           (int)kr_cfprefs, (int)kr_unlisted, shm, syslog_rc,
           fd_man, fd_log, fd_tz, fd_zero, fd_dtrace);
    return 0;
}
`
		if err := os.WriteFile(cFile, []byte(cSrc), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("/usr/bin/cc", "-o", binFile, cFile).CombinedOutput(); err != nil {
			t.Fatalf("compile darwin_probe: %v: %s", err, out)
		}
		if err := os.Chmod(binFile, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd, _, err := Command(HelperConfig{
			Policy:     DefaultPolicy(binFile),
			WorkerPath: binFile,
		})
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("run darwin_probe under sandbox-exec: %v (stderr=%q)", err, cmd.Stderr)
		}
		got := strings.TrimSpace(string(out))
		want := "cfprefs=1100 unlisted=1100 shm=-1 syslog=-1 man=-1 log=-1 tz=-1 zero=-1 dtrace=-1"
		if got != want {
			t.Fatalf("darwin_probe = %q, want %q", got, want)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil || !strings.HasPrefix(home, "/Users/") {
		return
	}
	canary := filepath.Join(home, ".ssh")
	if _, err := os.Stat(canary); err != nil {
		canary = home
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(exe, canary+"/") && exe != canary {
		cmd, _, err := Command(HelperConfig{
			Policy:     DefaultPolicy("/usr/bin/stat"),
			WorkerPath: "/usr/bin/stat",
			WorkerArgs: []string{canary},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Run(); err == nil {
			t.Fatalf("stat(%q) succeeded under HelperPolicy", canary)
		}
	}
}

func TestDarwinStageDoesNotLeakPolicyPathsInPs(t *testing.T) {
	if !Available() {
		t.Skip("sandbox-exec unavailable")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	secretPath := "/tmp/ntconfine-secret-stage-path-778899.mp4"
	pol := DefaultPolicy(exe, secretPath)
	proc, err := confine.StartStage(exe, nil, confine.StageSpec{
		Version:    SpecVersion,
		Policy:     pol,
		WorkerPath: exe,
		WorkerArgs: []string{sleepMarker},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Close() }()

	time.Sleep(100 * time.Millisecond)
	out, err := exec.Command("/bin/ps", "-o", "command=", "-p", strconv.Itoa(proc.PID())).CombinedOutput()
	if err != nil {
		t.Fatalf("ps -p %d: %v (%s)", proc.PID(), err, out)
	}
	if strings.Contains(string(out), "ntconfine-secret-stage-path-778899") {
		t.Fatalf("stage process leaked ReadPaths entry in ps output: %q", string(out))
	}
}
