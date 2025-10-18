package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
)

// Options configure daemon lifecycle behaviour.
type Options struct {
	ConfigPath string
	PIDFile    string
	LogFile    string
}

// ProcessStatus reflects the current state of a daemonised process.
type ProcessStatus struct {
	PID     int
	Running bool
}

// Run loads configuration, writes optional pid/log files, and executes the gateway runtime.
func Run(ctx context.Context, opts Options) error {
	cleanupPID, err := writePIDFile(opts.PIDFile)
	if err != nil {
		return err
	}
	defer cleanupPID()

	logCloser, err := setupLogFile(opts.LogFile)
	if err != nil {
		return err
	}
	defer logCloser()

	loadOpts := []gatewayconfig.Option{}
	if strings.TrimSpace(opts.ConfigPath) != "" {
		loadOpts = append(loadOpts, gatewayconfig.WithPath(opts.ConfigPath))
	}

	cfg, err := gatewayconfig.Load(loadOpts...)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	rt, err := gatewayruntime.New(cfg)
	if err != nil {
		return fmt.Errorf("build runtime: %w", err)
	}

	if err := rt.Start(ctx); err != nil {
		return err
	}
	return rt.Wait()
}

// Status inspects the PID file and determines if the daemon process is still running.
func Status(pidPath string) (ProcessStatus, error) {
	pid, err := readPIDFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return ProcessStatus{}, nil
	}
	if err != nil {
		return ProcessStatus{}, err
	}

	status := ProcessStatus{PID: pid}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return status, fmt.Errorf("find process: %w", err)
	}
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		status.Running = true
	} else {
		status.Running = false
	}
	return status, nil
}

// Stop sends the provided signal (defaults to SIGTERM) to the daemon process referenced by the PID file.
func Stop(pidPath string, sig syscall.Signal) (ProcessStatus, error) {
	if sig == 0 {
		sig = syscall.SIGTERM
	}

	status, err := Status(pidPath)
	if err != nil {
		return status, err
	}
	if status.PID == 0 {
		return status, os.ErrNotExist
	}
	if !status.Running {
		return status, nil
	}

	proc, err := os.FindProcess(status.PID)
	if err != nil {
		return status, fmt.Errorf("find process: %w", err)
	}
	if err := proc.Signal(sig); err != nil {
		return status, fmt.Errorf("signal process: %w", err)
	}
	return status, nil
}

func writePIDFile(path string) (func(), error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return func() {}, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return func() {}, fmt.Errorf("ensure pid directory: %w", err)
	}

	if _, err := readPIDFile(path); err == nil {
		return func() {}, fmt.Errorf("pid file %s already exists", path)
	}

	tmp := []byte(fmt.Sprintf("%d\n", os.Getpid()))
	if err := os.WriteFile(path, tmp, 0o644); err != nil {
		return func() {}, fmt.Errorf("write pid file: %w", err)
	}

	return func() {
		_ = os.Remove(path)
	}, nil
}

func readPIDFile(path string) (int, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return 0, fmt.Errorf("pid file path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, os.ErrNotExist
		}
		return 0, fmt.Errorf("read pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse pid: %w", err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid value %d", pid)
	}
	return pid, nil
}

func setupLogFile(path string) (func(), error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return func() {}, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return func() {}, fmt.Errorf("ensure log directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return func() {}, fmt.Errorf("open log file: %w", err)
	}

	if err := os.Setenv("APIGW_LOG_PATH", path); err != nil {
		_ = file.Close()
		return func() {}, fmt.Errorf("set log env: %w", err)
	}

	return func() {
		_ = file.Close()
	}, nil
}

// WaitSignal blocks until SIGTERM is received or the provided context completes.
func WaitSignal(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-ctx.Done():
	case <-sigCh:
	}
}
