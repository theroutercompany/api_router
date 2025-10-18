package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWritePIDFileCreatesAndCleans(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "apigw.pid")
	cleanup, err := writePIDFile(tmp)
	if err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("expected pid %d, got %d", os.Getpid(), pid)
	}

	cleanup()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("expected pid file removed, got err=%v", err)
	}
}

func TestWritePIDFileFailsWhenExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apigw.pid")
	if err := os.WriteFile(path, []byte("12345\n"), 0o644); err != nil {
		t.Fatalf("seed pid file: %v", err)
	}

	if _, err := writePIDFile(path); err == nil {
		t.Fatalf("expected error when pid file exists")
	}
}

func TestSetupLogFileSetsEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.log")

	closeFn, err := setupLogFile(path)
	if err != nil {
		t.Fatalf("setupLogFile: %v", err)
	}
	defer closeFn()

	if env := os.Getenv("APIGW_LOG_PATH"); env != path {
		t.Fatalf("expected env APIGW_LOG_PATH=%s, got %s", path, env)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected log file created: %v", err)
	}
}

func TestStatusHandlesMissingPID(t *testing.T) {
	status, err := Status(filepath.Join(t.TempDir(), "missing.pid"))
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Running || status.PID != 0 {
		t.Fatalf("expected no process, got %+v", status)
	}
}

func TestStatusReportsCurrentProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	status, err := Status(path)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.PID != os.Getpid() || !status.Running {
		t.Fatalf("expected running status for current pid, got %+v", status)
	}
}

func TestStopSendsSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on Windows in tests")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDaemonHelperProcess", "--", "daemon-helper")
	cmd.Env = append(os.Environ(), "APIGW_DAEMON_TEST_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	defer cmd.Process.Kill()

	pidPath := filepath.Join(t.TempDir(), "pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	status, err := Stop(pidPath, syscall.SIGTERM)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if status.PID != cmd.Process.Pid {
		t.Fatalf("expected pid %d, got %d", cmd.Process.Pid, status.PID)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("helper exit: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for helper to exit")
	}
}

func TestDaemonHelperProcess(t *testing.T) {
	if os.Getenv("APIGW_DAEMON_TEST_HELPER") != "1" {
		return
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-time.After(5 * time.Second):
	}
	os.Exit(0)
}
