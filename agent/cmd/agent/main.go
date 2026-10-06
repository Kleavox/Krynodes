package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/actions"
	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/cycle"
	"github.com/Kleavox/krynodes/agent/internal/host"
	"github.com/Kleavox/krynodes/agent/internal/metrics"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/stream"
	"github.com/Kleavox/krynodes/agent/internal/update"
)

var version = "dev"

const (
	accountName       = "kry"
	unitName          = "krynodes"
	defaultConfigPath = "/etc/kry/config.json"
	unitPath          = "/etc/systemd/system/krynodes.service"
	updaterPath       = "/etc/systemd/system/krynodes-update.service"
	watcherPath       = "/etc/systemd/system/krynodes-update.path"
	execPath          = "/etc/systemd/system/krynodes-exec.service"
	execWatcherPath   = "/etc/systemd/system/krynodes-exec.path"
	execTimerPath     = "/etc/systemd/system/krynodes-exec.timer"
	hostPath          = "/etc/systemd/system/krynodes-host.service"
	hostWatcherPath   = "/etc/systemd/system/krynodes-host.path"
	stateDirectory    = "/var/lib/kry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	command := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "run":
		return runDaemon(args, false)
	case "once":
		return runDaemon(args, true)
	case "enroll":
		return enroll(args)
	case "status":
		return status(args)
	case "metrics":
		return printMetrics()
	case "install-service":
		return installService(args)
	case "uninstall-service":
		return uninstallService(args)
	case "self-update":
		return selfUpdate()
	case "exec":
		return execActions()
	case "host-apply":
		return hostApply()
	case "setup":
		return setupCommand(args)
	case "trust":
		return trustDevices(args)
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

type trustOptions struct {
	initial bool
	reset   bool
	origin  string
	config  string
	keys    []string
	grant   bool
}

func parseTrust(args []string) (trustOptions, error) {
	var options trustOptions
	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	flags.BoolVar(&options.initial, "initial", false, "trust the first devices")
	flags.BoolVar(&options.reset, "reset", false, "forget every trusted device")
	flags.BoolVar(&options.grant, "grant", false, "let the trusted devices reach this server")
	flags.StringVar(&options.origin, "origin", "", "the dashboard origin, such as https://kry.kleavox.xyz")
	flags.StringVar(&options.config, "config", defaultConfigPath, "path to the agent config")
	if err := flags.Parse(args); err != nil {
		return trustOptions{}, err
	}
	options.keys = flags.Args()
	return options, nil
}

func trustDevices(args []string) error {
	options, err := parseTrust(args)
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("trust must run as root on Linux")
	}
	if options.reset {
		if err := actions.SaveTrust(actions.StateDir, actions.Trust{}); err != nil {
			return err
		}
		fmt.Println("This server trusts no device now.")
		return nil
	}
	if !options.initial {
		return fmt.Errorf("use --initial --origin <origin> -- <device>... or --reset")
	}
	current, err := actions.LoadTrust(actions.StateDir)
	if err != nil {
		return err
	}
	if len(current.Core) > 0 {
		return fmt.Errorf("this server already trusts devices; run kry trust --reset first")
	}
	cfg, err := config.Load(options.config)
	if err != nil {
		return err
	}
	trust, err := actions.ParseTrustArgs(options.origin, options.keys, options.grant)
	if err != nil {
		return err
	}
	trust.NodeID = cfg.NodeID
	if err := actions.SaveTrust(actions.StateDir, trust); err != nil {
		return err
	}
	fmt.Printf("This server trusts %d devices; %d reach it.\n", len(trust.Core), len(trust.Access))
	return nil
}

func printMetrics() error {
	snapshot, err := metrics.Collect()
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func enroll(args []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "https://kry.example.com", "Krynodes endpoint")
	token := flags.String("token", "", "one-time enrollment token")
	configPath := flags.String("config", defaultConfigPath, "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*token) == "" {
		return fmt.Errorf("--token is required")
	}

	host, err := currentHost()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	enrollment, err := reporter.New(*endpoint, *token, version).Enroll(ctx, host)
	if err != nil {
		return describeResponseError("enrollment", err)
	}

	cfg := config.Config{
		Endpoint:        *endpoint,
		NodeID:          enrollment.NodeID,
		Token:           enrollment.Token,
		IntervalSeconds: enrollment.IntervalSeconds,
	}
	if err := config.Save(*configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("Enrolled node %s and wrote %s\n", enrollment.NodeID, *configPath)
	return nil
}

func runDaemon(args []string, once bool) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath, "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	host, err := currentHost()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := stream.New(cfg.Endpoint, cfg.Token, version)
	connection, closeConnection := context.WithCancel(ctx)
	closed := make(chan struct{})
	go func() {
		client.Run(connection)
		close(closed)
	}()
	defer func() {
		closeConnection()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
		}
	}()
	relay := &actions.Relay{
		RequestDir: actions.RequestDir,
		StateDir:   actions.StateDir,
		NodeID:     cfg.NodeID,
		Server:     client,
		Now:        time.Now,
	}
	monitoringCycle := cycle.New(client, host, requestFile{}, relay)

	if once {
		if err := client.WaitConnected(ctx, 30*time.Second); err != nil {
			return fmt.Errorf("connect to Krynodes: %w", err)
		}
		_, err := monitoringCycle.Execute(ctx, cfg.NodeID)
		return err
	}

	log.Printf("%s %s started for node %s", unitName, version, cfg.NodeID)
	go relay.Watch(ctx, 2*time.Second)
	if err := client.WaitConnected(ctx, 15*time.Second); err == nil {
		select {
		case <-client.Ready():
		default:
		}
	}
	interval := cfg.Interval
	for {
		nextInterval, err := monitoringCycle.Execute(ctx, cfg.NodeID)
		if err != nil {
			log.Printf("monitoring cycle failed: %v", err)
		} else if nextInterval >= 15 && nextInterval <= 3600 {
			interval = time.Duration(nextInterval) * time.Second
		}
		if err == nil && monitoringCycle.ConfigChanged() {
			continue
		}
		timer := time.NewTimer(untilNextTick(time.Now(), interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			log.Printf("%s stopped", unitName)
			return nil
		case <-timer.C:
		case <-client.Pokes():
			timer.Stop()
		case <-client.Ready():
			timer.Stop()
		}
	}
}

const tickOffset = 2 * time.Second

func untilNextTick(now time.Time, interval time.Duration) time.Duration {
	since := time.Duration(now.UnixNano()) - tickOffset
	return interval - since%interval
}

func status(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath, "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	fmt.Printf("Node: %s\nEndpoint: %s\nInterval: %s\n", cfg.NodeID, cfg.Endpoint, cfg.Interval)
	return nil
}

func installService(args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd installation is supported only on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install-service must run as root")
	}
	flags := flag.NewFlagSet("install-service", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath, "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if _, err := config.Load(*configPath); err != nil {
		return err
	}
	uid, gid, err := ensureServiceUser(*configPath)
	if err != nil {
		return err
	}
	if err := prepareActionDirectories(uid, gid); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}

	units := map[string]string{
		unitPath:        serviceUnit(executable, *configPath),
		updaterPath:     updaterUnit(executable),
		watcherPath:     pathUnit(),
		execPath:        execUnit(executable),
		execWatcherPath: execPathUnit(),
		execTimerPath:   execTimerUnit(),
		hostPath:        hostUnit(executable),
		hostWatcherPath: hostPathUnit(),
	}
	for path, unit := range units {
		if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
			return err
		}
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	for _, name := range enabledUnits() {
		if err := exec.Command("systemctl", "enable", "--now", name).Run(); err != nil {
			return fmt.Errorf("enable %s: %w", name, err)
		}
	}
	fmt.Printf("Installed and started %s.service\n", unitName)
	return nil
}

func enabledUnits() []string {
	return []string{unitName + ".service", unitName + "-update.path", unitName + "-exec.path", unitName + "-exec.timer", unitName + "-host.path"}
}

func hostUnit(executable string) string {
	return fmt.Sprintf(`[Unit]
Description=Krynodes server recipes
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=%s host-apply
TimeoutStartSec=30min
PrivateTmp=true
Environment=DOCKER_CONFIG=%s/docker
`, executable, actions.StateDir)
}

func hostPathUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Watch for Krynodes server recipe requests

[Path]
DirectoryNotEmpty=%s/host
Unit=%s-host.service

[Install]
WantedBy=multi-user.target
`, actions.StateDir, unitName)
}

func serviceUnit(executable, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Krynodes Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[1]s
ExecStart=%[2]s run --config %[3]s
Restart=always
RestartSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
StateDirectory=%[1]s

[Install]
WantedBy=multi-user.target
`, accountName, executable, configPath)
}

func updaterUnit(executable string) string {
	return fmt.Sprintf(`[Unit]
Description=Krynodes Agent updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s self-update
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
`, executable)
}

func pathUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Watch for Krynodes Agent update requests

[Path]
PathChanged=%s
Unit=%s-update.service

[Install]
WantedBy=multi-user.target
`, update.RequestPath, unitName)
}

func execUnit(executable string) string {
	return fmt.Sprintf(`[Unit]
Description=Krynodes service actions
StartLimitIntervalSec=0

[Service]
Type=oneshot
Group=%s
ExecStart=%s exec
TimeoutStartSec=30min
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=%s
Environment=DOCKER_CONFIG=%s/docker
`, accountName, executable, actions.StateDir, actions.StateDir)
}

func execPathUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Watch for Krynodes service action requests

[Path]
PathChanged=%s
Unit=%s-exec.service

[Install]
WantedBy=multi-user.target
`, actions.RequestDir, unitName)
}

func execTimerUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Refresh the Krynodes service inventory

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=%s-exec.service

[Install]
WantedBy=timers.target
`, unitName)
}

func execActions() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("exec must run as root on Linux")
	}
	executor := actions.Executor{
		RequestDir: actions.RequestDir,
		StateDir:   actions.StateDir,
		Now:        time.Now,
		Run:        actions.RunCommand,
		Collect: func(ctx context.Context, remembered []string) (actions.Snapshot, error) {
			return actions.Collect(ctx, actions.RunCommand, remembered)
		},
		Audit: true,
	}
	return executor.Execute(context.Background())
}

func hostApply() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("host-apply must run as root on Linux")
	}
	executor := actions.Executor{StateDir: actions.StateDir, Now: time.Now, Run: actions.RunCommand}
	return executor.HostApply(context.Background())
}

func prepareActionDirectories(uid, gid int) error {
	if err := claimDirectory(actions.RequestDir, uid, gid, 0o750); err != nil {
		return fmt.Errorf("prepare action request directory: %w", err)
	}
	for _, directory := range []string{actions.StateDir, filepath.Join(actions.StateDir, "results")} {
		if err := claimDirectory(directory, 0, gid, 0o750); err != nil {
			return fmt.Errorf("prepare %s: %w", directory, err)
		}
	}
	return nil
}

type requestFile struct{}

func (requestFile) Failure() *reporter.UpdateFailure {
	status, ok := update.ReadStatus(update.StatusPath, version)
	if !ok {
		return nil
	}
	return &reporter.UpdateFailure{Version: status.Version, Message: status.Message}
}

func (requestFile) Request(version, requestedAt string) error {
	changed, err := update.WriteRequest(update.RequestPath, version, requestedAt)
	if changed {
		log.Printf("requested an update to %s", version)
	}
	return err
}

func selfUpdate() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("self-update must run as root on Linux")
	}
	key, err := update.PublicKey()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	err = update.Apply(update.Options{
		RequestPath:    update.RequestPath,
		StatusPath:     update.StatusPath,
		BinaryPath:     executable,
		Base:           update.DefaultBase,
		Arch:           runtime.GOARCH,
		CurrentVersion: version,
		PublicKey:      key,
		Client:         updateClient(),
		Run: func(name string, args ...string) error {
			return exec.Command(name, args...).Run()
		},
		Output: func(name string, args ...string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, name, args...).Output()
			return string(output), err
		},
	})
	if err != nil {
		log.Printf("update failed: %v", err)
	}
	return err
}

func ensureServiceUser(configPath string) (int, int, error) {
	account, err := user.Lookup(accountName)
	if err != nil {
		if createErr := exec.Command(
			"useradd", "--system", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", accountName,
		).Run(); createErr != nil {
			return 0, 0, fmt.Errorf("create %s user: %w", accountName, createErr)
		}
		account, err = user.Lookup(accountName)
		if err != nil {
			return 0, 0, fmt.Errorf("lookup %s user: %w", accountName, err)
		}
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, err
	}
	if err := os.MkdirAll(stateDirectory, 0o755); err != nil {
		return 0, 0, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chown(stateDirectory, uid, gid); err != nil {
		return 0, 0, fmt.Errorf("set state directory ownership: %w", err)
	}
	if err := os.Chown(filepath.Dir(configPath), uid, gid); err != nil {
		return 0, 0, fmt.Errorf("set config directory ownership: %w", err)
	}
	if err := claimFile(configPath, uid, gid, 0o600); err != nil {
		return 0, 0, fmt.Errorf("set config ownership: %w", err)
	}
	return uid, gid, nil
}

func uninstallService(args []string) error {
	deleteApps := false
	for _, arg := range args {
		if arg != "--delete-apps" {
			return fmt.Errorf("unknown flag %q; the only one is --delete-apps", arg)
		}
		deleteApps = true
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("uninstall-service must run as root on Linux")
	}
	for _, command := range uninstallCommands() {
		_ = exec.Command(command[0], command[1:]...).Run()
	}
	executor := actions.Executor{StateDir: actions.StateDir, Now: time.Now, Run: actions.RunCommand}
	removal := executor.Uninstall(context.Background(), deleteApps)
	binary, _ := os.Executable()
	for _, path := range leftovers(binary) {
		if err := os.RemoveAll(path); err != nil {
			removal.Problems = append(removal.Problems, fmt.Sprintf("remove %s: %v", path, err))
		}
	}
	_ = exec.Command("userdel", accountName).Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("Krynodes is removed from this server.")
	for _, line := range removal.TurnedOff {
		fmt.Println("  Turned off: " + line)
	}
	for _, line := range removal.Apps {
		fmt.Println("  " + line)
	}
	if removal.Docker != "" {
		fmt.Println("  " + removal.Docker)
	}
	fmt.Println("If this server is still in the dashboard, delete it there too; that also removes its Cloudflare tunnel, DNS records and login.")
	if len(removal.Problems) > 0 {
		return fmt.Errorf("some parts need a look:\n  %s", strings.Join(removal.Problems, "\n  "))
	}
	return nil
}

func leftovers(binary string) []string {
	paths := []string{hostWatcherPath, hostPath, execTimerPath, execWatcherPath, execPath, watcherPath, updaterPath, unitPath, stateDirectory, path.Dir(defaultConfigPath)}
	if binary != "" {
		paths = append(paths, binary)
	}
	return paths
}

func uninstallCommands() [][]string {
	return [][]string{
		{"systemctl", "disable", "--now", unitName + "-host.path", unitName + "-exec.timer", unitName + "-exec.path", unitName + "-update.path", unitName + ".service"},
		{"systemctl", "stop", unitName + "-exec.service", unitName + "-host.service"},
	}
}

func currentHost() (reporter.Host, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return reporter.Host{}, fmt.Errorf("read hostname: %w", err)
	}
	return reporter.Host{
		Hostname: hostname, OperatingSystem: host.OperatingSystem(),
		Architecture: runtime.GOARCH, AgentVersion: version,
	}, nil
}

func describeResponseError(action string, err error) error {
	var responseError *reporter.ResponseError
	if errors.As(err, &responseError) {
		return fmt.Errorf("%s failed with HTTP %d: %s", action, responseError.Status, strings.TrimSpace(responseError.Body))
	}
	return fmt.Errorf("%s failed: %w", action, err)
}

func updateClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       reporter.TLSConfig(),
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
	}}
}
