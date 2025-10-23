package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	gatewayconfig "github.com/theroutercompany/api_router/pkg/gateway/config"
	gatewaydaemon "github.com/theroutercompany/api_router/pkg/gateway/daemon"
	gatewayruntime "github.com/theroutercompany/api_router/pkg/gateway/runtime"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = runCommand(os.Args[2:])
	case "validate":
		err = validateCommand(os.Args[2:])
	case "init":
		err = initCommand(os.Args[2:])
	case "daemon":
		err = daemonCommand(os.Args[2:])
	case "admin":
		err = adminCommand(os.Args[2:])
	case "convert-env":
		err = convertEnvCommand(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("apigw %s: %v", os.Args[1], err)
	}
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to gateway configuration file")
	watch := fs.Bool("watch", false, "Watch the config file for changes and hot-reload")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := []gatewayconfig.Option{}
	if *configPath != "" {
		opts = append(opts, gatewayconfig.WithPath(*configPath))
	}

	cfg, err := gatewayconfig.Load(opts...)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	reloadRequests := make(chan gatewayconfig.Config, 1)
	enqueueReload := func(cfg gatewayconfig.Config) {
		select {
		case reloadRequests <- cfg:
		default:
			go func() { reloadRequests <- cfg }()
		}
	}

	reloadFunc := func() (gatewayconfig.Config, error) {
		cfg, err := gatewayconfig.Load(opts...)
		if err != nil {
			return gatewayconfig.Config{}, err
		}
		enqueueReload(cfg)
		return cfg, nil
	}

	rt, err := gatewayruntime.New(cfg, gatewayruntime.WithReloadFunc(reloadFunc))
	if err != nil {
		return fmt.Errorf("build runtime: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var (
		watchErrCh  <-chan error
		watchCancel context.CancelFunc
	)
	if *watch {
		if *configPath == "" {
			return errors.New("--config is required when --watch is enabled")
		}
		watchReloadCh, errCh, cancelWatch, err := watchConfig(ctx, *configPath, opts)
		if err != nil {
			return fmt.Errorf("watch config: %w", err)
		}
		watchErrCh = errCh
		watchCancel = cancelWatch
		go func() {
			for cfg := range watchReloadCh {
				enqueueReload(cfg)
			}
		}()
	}
	defer func() {
		if watchCancel != nil {
			watchCancel()
		}
	}()

	runCtx, runCancel := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() {
		runDone <- rt.Run(runCtx)
	}()

	for {
		select {
		case err := <-runDone:
			runCancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		case cfg := <-reloadRequests:
			runCancel()
			if err := <-runDone; err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			if err := rt.Reload(cfg); err != nil {
				return fmt.Errorf("reload config: %w", err)
			}
			runCtx, runCancel = context.WithCancel(ctx)
			runDone = make(chan error, 1)
			go func() {
				runDone <- rt.Run(runCtx)
			}()
			log.Printf("configuration reloaded")
		case err, ok := <-watchErrCh:
			if !ok {
				watchErrCh = nil
				continue
			}
			if err != nil {
				log.Printf("config watch error: %v", err)
			}
		case <-ctx.Done():
			runCancel()
		}
	}
}

func validateCommand(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to gateway configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := []gatewayconfig.Option{}
	if *configPath != "" {
		opts = append(opts, gatewayconfig.WithPath(*configPath))
	}

	if _, err := gatewayconfig.Load(opts...); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	fmt.Println("configuration valid")
	return nil
}

func initCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outputPath := fs.String("path", "apigw.yaml", "Destination path for generated config")
	force := fs.Bool("force", false, "Overwrite existing file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*force {
		if _, err := os.Stat(*outputPath); err == nil {
			return fmt.Errorf("config file %s already exists (use --force to overwrite)", *outputPath)
		}
	}

	if err := os.WriteFile(*outputPath, []byte(sampleConfigYAML), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("configuration written to %s\n", *outputPath)
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: apigw <command> [options]\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  run       Start the gateway using the provided config\n")
	fmt.Fprintf(os.Stderr, "  validate  Validate configuration without starting the gateway\n")
	fmt.Fprintf(os.Stderr, "  init      Generate a config skeleton\n")
	fmt.Fprintf(os.Stderr, "  daemon    Manage the gateway as a background process\n")
	fmt.Fprintf(os.Stderr, "  admin     Invoke admin control-plane endpoints (status/reload)\n")
	fmt.Fprintf(os.Stderr, "  convert-env  Snapshot environment variables into a YAML config\n")
}

const daemonChildEnv = "APIGW_DAEMON_CHILD"

func daemonCommand(args []string) error {
	subcommand := "start"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcommand = args[0]
		args = args[1:]
	}

	switch subcommand {
	case "start":
		return daemonStart(args)
	case "stop":
		return daemonStop(args)
	case "status":
		return daemonStatus(args)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", subcommand)
	}
}

func daemonStart(args []string) error {
	rawArgs := append([]string(nil), args...)
	fs := flag.NewFlagSet("daemon start", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to gateway configuration file")
	pidPath := fs.String("pid", "apigw.pid", "Path to write the PID file")
	logPath := fs.String("log", "", "Path to write daemon logs")
	background := fs.Bool("background", false, "Run the daemon in the background")
	if err := fs.Parse(args); err != nil {
		return err
	}

	isChild := os.Getenv(daemonChildEnv) == "1"
	if *background && !isChild {
		childArgs := []string{"daemon", "start"}
		for _, arg := range rawArgs {
			if strings.HasPrefix(arg, "--background") {
				continue
			}
			childArgs = append(childArgs, arg)
		}
		cmd := exec.Command(os.Args[0], childArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), daemonChildEnv+"=1")
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start background daemon: %w", err)
		}
		fmt.Fprintf(os.Stdout, "daemon started (pid %d)\n", cmd.Process.Pid)
		return nil
	}

	os.Unsetenv(daemonChildEnv)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	options := gatewaydaemon.Options{
		ConfigPath: *configPath,
		PIDFile:    *pidPath,
		LogFile:    *logPath,
	}

	return gatewaydaemon.Run(ctx, options)
}

func daemonStop(args []string) error {
	fs := flag.NewFlagSet("daemon stop", flag.ExitOnError)
	pidPath := fs.String("pid", "apigw.pid", "Path to PID file")
	signalName := fs.String("signal", "SIGTERM", "Signal to send (name or number)")
	wait := fs.Duration("wait", 5*time.Second, "Time to wait for shutdown")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sig, err := parseSignal(*signalName)
	if err != nil {
		return err
	}

	status, err := gatewaydaemon.Stop(*pidPath, sig)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stdout, "daemon not running (no pid file)")
		return nil
	}
	if err != nil {
		return fmt.Errorf("stop daemon: %w", err)
	}

	if !status.Running {
		fmt.Fprintln(os.Stdout, "daemon already stopped")
		_ = os.Remove(*pidPath)
		return nil
	}

	deadline := time.Now().Add(*wait)
	waitDur := *wait
	for {
		time.Sleep(200 * time.Millisecond)
		st, err := gatewaydaemon.Status(*pidPath)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stdout, "daemon stopped")
			_ = os.Remove(*pidPath)
			return nil
		}
		if err != nil {
			return fmt.Errorf("check status: %w", err)
		}
		if !st.Running {
			fmt.Fprintln(os.Stdout, "daemon stopped")
			_ = os.Remove(*pidPath)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon pid %d did not stop within %s", st.PID, waitDur)
		}
	}
}

func daemonStatus(args []string) error {
	fs := flag.NewFlagSet("daemon status", flag.ExitOnError)
	pidPath := fs.String("pid", "apigw.pid", "Path to PID file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	status, err := gatewaydaemon.Status(*pidPath)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if status.PID == 0 {
		fmt.Fprintln(os.Stdout, "daemon not running")
		return nil
	}
	if status.Running {
		fmt.Fprintf(os.Stdout, "daemon running (pid %d)\n", status.PID)
	} else {
		fmt.Fprintf(os.Stdout, "daemon stopped (stale pid %d)\n", status.PID)
	}
	return nil
}

func parseSignal(value string) (syscall.Signal, error) {
	if value == "" {
		return syscall.SIGTERM, nil
	}
	if n, err := strconv.Atoi(value); err == nil {
		return syscall.Signal(n), nil
	}

	switch strings.ToUpper(value) {
	case "TERM", "SIGTERM":
		return syscall.SIGTERM, nil
	case "KILL", "SIGKILL":
		return syscall.SIGKILL, nil
	case "INT", "SIGINT":
		return syscall.SIGINT, nil
	case "QUIT", "SIGQUIT":
		return syscall.SIGQUIT, nil
	default:
		return 0, fmt.Errorf("unsupported signal %q", value)
	}
}

func adminCommand(args []string) error {
	subcommand := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcommand = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("admin "+subcommand, flag.ExitOnError)
	baseURL := fs.String("url", "http://127.0.0.1:9090", "Base URL for the admin server")
	token := fs.String("token", "", "Bearer token for admin requests")
	timeout := fs.Duration("timeout", 5*time.Second, "HTTP request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{Timeout: *timeout}
	base := strings.TrimRight(*baseURL, "/")

	switch subcommand {
	case "status":
		return adminGET(client, base+"/__admin/status", *token)
	case "config":
		return adminGET(client, base+"/__admin/config", *token)
	case "reload":
		return adminPOST(client, base+"/__admin/reload", *token)
	default:
		return fmt.Errorf("unknown admin subcommand %q", subcommand)
	}
}

func adminGET(client *http.Client, url, token string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s", strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

func adminPOST(client *http.Client, url, token string) error {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin reload failed: %s", strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		fmt.Println(string(body))
	} else {
		fmt.Println("reload requested")
	}
	return nil
}

func watchConfig(parent context.Context, path string, opts []gatewayconfig.Option) (<-chan gatewayconfig.Config, <-chan error, context.CancelFunc, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve config path: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, nil, err
	}
	dir := filepath.Dir(absPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return nil, nil, nil, fmt.Errorf("watch directory: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	reloadCh := make(chan gatewayconfig.Config)
	errCh := make(chan error, 1)

	go func() {
		defer close(reloadCh)
		defer close(errCh)
		defer watcher.Close()

		var debounce <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-watcher.Events:
				if !ok {
					return
				}
				if !targetsFile(evt.Name, absPath) {
					continue
				}
				if evt.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}
				debounce = time.After(200 * time.Millisecond)
			case <-debounce:
				cfg, err := gatewayconfig.Load(opts...)
				if err != nil {
					errCh <- err
					debounce = nil
					continue
				}
				select {
				case reloadCh <- cfg:
				case <-ctx.Done():
				}
				debounce = nil
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				errCh <- err
			}
		}
	}()

	return reloadCh, errCh, cancel, nil
}

func convertEnvCommand(args []string) error {
	fs := flag.NewFlagSet("convert-env", flag.ExitOnError)
	configPath := fs.String("config", "", "Optional config file to merge before env overrides")
	outputPath := fs.String("output", "", "Destination path for generated YAML (stdout when empty)")
	force := fs.Bool("force", false, "Overwrite existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := []gatewayconfig.Option{}
	if strings.TrimSpace(*configPath) != "" {
		opts = append(opts, gatewayconfig.WithPath(*configPath))
	}

	cfg, err := gatewayconfig.Load(opts...)
	if err != nil {
		return fmt.Errorf("load config from environment: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	path := strings.TrimSpace(*outputPath)
	if path == "" {
		fmt.Print(string(data))
		return nil
	}

	if !*force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output file %s already exists (use --force to overwrite)", path)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat output file: %w", err)
		}
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("ensure output directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	fmt.Printf("configuration written to %s\n", path)
	return nil
}

func targetsFile(eventPath, target string) bool {
	if eventPath == "" {
		return false
	}
	abs, err := filepath.Abs(eventPath)
	if err != nil {
		return false
	}
	return abs == target
}

const sampleConfigYAML = `# Gateway configuration for the API router.
version: ""

http:
  port: 8080
  shutdownTimeout: 15s

readiness:
  timeout: 2s
  userAgent: api-router-gateway/readyz
  upstreams:
    - name: trade
      baseURL: https://trade.example.com
      healthPath: /health
      tls:
        enabled: false
        insecureSkipVerify: false
        caFile: ""
        clientCertFile: ""
        clientKeyFile: ""
    - name: task
      baseURL: https://task.example.com
      healthPath: /health
      tls:
        enabled: false
        insecureSkipVerify: false
        caFile: ""
        clientCertFile: ""
        clientKeyFile: ""

auth:
  secret: replace-me
  issuer: router
  audiences:
    - api

cors:
  allowedOrigins:
    - https://app.example.com

rateLimit:
  window: 60s
  max: 120

metrics:
  enabled: true
`
