package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/host"
	"github.com/Kleavox/krynodes/agent/internal/mesh"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/stacks"
	"github.com/Kleavox/krynodes/agent/internal/stream"
	"github.com/Kleavox/krynodes/agent/internal/trust"
	"github.com/Kleavox/krynodes/agent/internal/update"
)

var version = "dev"

const (
	configDir   = "/etc/kry"
	configPath  = configDir + "/config.json"
	stateDir    = "/var/lib/kry"
	unitPath    = "/etc/systemd/system/krynodes.service"
	binPath     = "/usr/local/bin/kry"
	sudoLink    = "/usr/bin/kry"
	unitName    = "krynodes.service"
	ackWait     = 10 * time.Second
	updateGrace = 10 * time.Second
	usage       = "usage: kry run | enroll --endpoint <url> --token <code> --origin <dashboard> --trust <id.alg.key,...> | install-service | uninstall-service [--delete-apps] | self-update | trust --reset --origin <dashboard> --trust <id.alg.key,...> | network fingerprint | network rules | version"
)

const unit = `[Unit]
Description=Krynodes
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=` + binPath + ` run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

var removed = []string{unitPath, configDir, stateDir, binPath, binPath + ".previous", binPath + ".new"}

func main() {
	os.Setenv("PATH", systemFirst(os.Getenv("PATH")))
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func systemFirst(path string) string {
	var system, local []string
	for _, dir := range strings.Split(path, ":") {
		if strings.HasPrefix(dir, "/usr/local/") {
			local = append(local, dir)
		} else {
			system = append(system, dir)
		}
	}
	return strings.Join(append(system, local...), ":")
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	bare := len(args) == 1
	var err error
	switch {
	case args[0] == "version" && bare:
		fmt.Fprintln(stdout, version)
		return 0
	case args[0] == "run":
		err = runDaemon(args[1:])
	case args[0] == "enroll":
		err = enroll(args[1:], stdout)
	case args[0] == "install-service" && bare:
		err = installService(stdout)
	case args[0] == "uninstall-service" && (bare || len(args) == 2 && args[1] == "--delete-apps"):
		err = uninstallService(!bare, stdout)
	case args[0] == "self-update" && bare:
		err = selfUpdate()
	case args[0] == "trust":
		err = resetTrust(args[1:], stdout)
	case args[0] == "network" && len(args) == 2 && (args[1] == "fingerprint" || args[1] == "rules"):
		err = networkCommand(args[1], stdout)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func asRoot(command string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("kry %s must run as root on Linux", command)
	}
	return nil
}

type facts struct {
	Hostname, OS, Arch, Kernel string
}

func currentFacts() facts {
	hostname, _ := os.Hostname()
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return facts{hostname, host.OperatingSystem(), runtime.GOARCH, strings.TrimSpace(string(kernel))}.known()
}

func (f facts) known() facts {
	for _, value := range []*string{&f.Hostname, &f.OS, &f.Arch, &f.Kernel} {
		if strings.TrimSpace(*value) == "" {
			*value = "unknown"
		}
	}
	return f
}

func hello(f facts, sealKey string, current trust.Trust, network *reporter.NetworkHello) reporter.Hello {
	message := reporter.Hello{Type: "hello", V: 1, Version: version, Hostname: f.Hostname, OS: f.OS, Arch: f.Arch, Kernel: f.Kernel, Kind: "server", SealKey: sealKey, Network: network}
	if len(current.Core) > 0 {
		report := current.Report()
		message.Trust = &report
	}
	return message
}

func tokens(list string) []string {
	if list == "" {
		return nil
	}
	return strings.Split(list, ",")
}

type enrollOptions struct {
	endpoint, token, origin string
	trust                   []string
}

func enroll(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	var options enrollOptions
	var list string
	flags.StringVar(&options.endpoint, "endpoint", "", "Krynodes endpoint")
	flags.StringVar(&options.token, "token", "", "one-time enrollment code")
	flags.StringVar(&options.origin, "origin", "", "your dashboard's origin")
	flags.StringVar(&list, "trust", "", "the passkeys to trust, as id.alg.key separated by commas")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := asRoot("enroll"); err != nil {
		return err
	}
	options.trust = tokens(list)
	node, err := enrollWith(secureClient(), options, currentFacts(), configPath, stateDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Enrolled as server %s.\n", node)
	return nil
}

func enrollWith(client *http.Client, options enrollOptions, f facts, configPath, state string) (string, error) {
	if _, err := os.Stat(configPath); err == nil {
		enrolled := "another server"
		if cfg, err := config.Load(configPath); err == nil {
			enrolled = cfg.NodeID
		}
		return "", fmt.Errorf("this server is already enrolled as %s; to enroll it again, remove Krynodes first with: sudo kry uninstall-service", enrolled)
	}
	if strings.TrimSpace(options.token) == "" {
		return "", errors.New("--token is required")
	}
	if err := config.Valid(config.Config{Endpoint: options.endpoint, NodeID: "-", Token: "-"}); err != nil {
		return "", err
	}
	if _, err := trust.FirstTrust("-", options.origin, options.trust); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"hostname": f.Hostname, "os": f.OS, "arch": f.Arch, "kernel": f.Kernel, "version": version})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(options.endpoint, "/")+"/api/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+options.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "kry-agent/"+version)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("enrollment failed with HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(answer[:min(len(answer), 512)])))
	}
	var enrolled struct {
		NodeID string `json:"nodeId"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(answer, &enrolled); err != nil || enrolled.NodeID == "" || enrolled.Token == "" {
		return "", errors.New("enrollment failed: Krynodes answered without a server id and token")
	}
	if err := config.Save(configPath, config.Config{Endpoint: options.endpoint, NodeID: enrolled.NodeID, Token: enrolled.Token}); err != nil {
		return "", err
	}
	first, err := trust.FirstTrust(enrolled.NodeID, options.origin, options.trust)
	if err != nil {
		return "", err
	}
	if err := trust.Save(state, first); err != nil {
		return "", err
	}
	if _, err := seal.Load(state); err != nil {
		return "", err
	}
	if err := (&mesh.Mesh{State: state}).Ensure(ctx); err != nil {
		return "", fmt.Errorf("make the network keys: %w", err)
	}
	return enrolled.NodeID, nil
}

func runDaemon(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	path := flags.String("config", configPath, "configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := asRoot("run"); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	key, err := seal.Load(stateDir)
	if err != nil {
		return err
	}
	executable, err := self()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := stream.New(cfg.Endpoint, cfg.Token, version)
	d := &daemon.Daemon{
		State: stateDir,
		Trust: func() trust.Trust {
			current, err := trust.Load(stateDir)
			if err != nil {
				log.Print(err)
			}
			return current
		},
		SaveTrust: func(next trust.Trust) error { return trust.Save(stateDir, next) },
		Send:      client.Send,
		Now:       time.Now,
		Resume:    daemon.Resume(version, updateFailure),
	}
	sealKey := seal.Public(key)
	network := &mesh.Mesh{State: stateDir, Executable: executable, Run: runCommand, Now: time.Now, Trust: d.Trust, SealKey: func() string { return sealKey }, Send: client.Send,
		Unseal: func(sealed string) ([]byte, error) { return seal.Open(key, sealed) },
		Left: func() {
			if err := client.HelloAgain(); err != nil {
				log.Printf("tell Krynodes the new network keys: %v", err)
			}
		}}
	if err := network.Ensure(ctx); err != nil {
		log.Printf("make the network keys: %v", err)
	}
	d.Handlers = map[string]daemon.Handler{
		"trust/apply":  d.ApplyTrust,
		"agent/update": daemon.Update(version, updateGrace, updater(executable)),
		"host/restart": daemon.AfterAck(d, ackWait, "Restarting now.", func() { runLogged("systemctl", "reboot") }),
		"agent/remove": daemon.AfterAck(d, ackWait, "Removing Krynodes from this server.", func() {
			runLogged("systemd-run", "--unit=krynodes-remove", "--collect", "--quiet", executable, "uninstall-service")
		}),
	}
	maps.Copy(d.Handlers, network.Handlers())
	stacks.ClearTemp(os.TempDir())
	checks := docker.NewChecks()
	apps := stacks.Env{Run: runCommand, State: stateDir, Server: currentFacts().Hostname, Own: network.Own, Checks: checks, Now: time.Now,
		Unseal:   func(sealed string) ([]byte, error) { return seal.Open(key, sealed) },
		Platform: platform.Env{Run: platform.Runner(runCommand)}}
	maps.Copy(d.Handlers, stacks.Handlers(apps))
	client.Hello = func() any { return hello(currentFacts(), sealKey, d.Trust(), network.Hello(ctx)) }
	client.Connected = func() {
		d.Resend()
		checks.Restate()
	}
	client.Command = func(command reporter.Command) { go d.Handle(ctx, command) }
	client.Ack = d.Ack
	client.Network = networkWorker(ctx, network)
	client.Checks = func(chosen reporter.Checks) { checks.Choose(chosen.Names) }
	go docker.Watch(ctx, runCommand, client.Send, checks, apps.Meta(ctx))
	go apps.GuardContained(ctx, 10*time.Second)
	go apps.SweepRemoved(ctx, time.Hour)
	go network.Guard(ctx, 10*time.Second)
	go network.WatchLinks(ctx, 10*time.Second)
	go d.Start(ctx)
	log.Printf("krynodes %s started for server %s", version, cfg.NodeID)
	client.Run(ctx)
	log.Printf("krynodes stopped")
	return nil
}

const (
	maxHints     = 32
	maxDocuments = 64
)

func networkWorker(ctx context.Context, network *mesh.Mesh) func(any) {
	var mu sync.Mutex
	var documents []reporter.Document
	var hints []reporter.Hints
	var refreshing atomic.Bool
	wake := make(chan struct{}, 1)
	next := func() (any, bool) {
		mu.Lock()
		defer mu.Unlock()
		if len(documents) > 0 {
			document := documents[0]
			documents = documents[1:]
			return document, true
		}
		if len(hints) > 0 {
			hint := hints[0]
			hints = hints[1:]
			return hint, true
		}
		return nil, false
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
			}
			for message, ok := next(); ok; message, ok = next() {
				switch value := message.(type) {
				case reporter.Document:
					network.Document(ctx, value.Version, value.Signed)
				case reporter.Hints:
					network.Hints(ctx, value)
				}
			}
		}
	}()
	return func(message any) {
		switch value := message.(type) {
		case reporter.Refresh:
			if !refreshing.CompareAndSwap(false, true) {
				return
			}
			go func() {
				defer refreshing.Store(false)
				if err := network.SendLinks(ctx); err != nil {
					log.Printf("private network links: %v", err)
				}
			}()
			return
		case reporter.Document:
			mu.Lock()
			documents = append(slices.DeleteFunc(documents, func(queued reporter.Document) bool { return queued.Version == value.Version }), value)
			slices.SortFunc(documents, func(a, b reporter.Document) int { return cmp.Compare(a.Version, b.Version) })
			documents = documents[:min(len(documents), maxDocuments)]
			mu.Unlock()
		case reporter.Hints:
			mu.Lock()
			if hints = append(hints, value); len(hints) > maxHints {
				hints = hints[len(hints)-maxHints:]
			}
			mu.Unlock()
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return output, exit.ExitCode(), err
	}
	if err != nil {
		return output, -1, err
	}
	return output, 0, nil
}

func localMesh(state string) *mesh.Mesh {
	return &mesh.Mesh{
		State: state,
		Run:   runCommand,
		Now:   time.Now,
		Trust: func() trust.Trust {
			current, _ := trust.Load(state)
			return current
		},
		SealKey: func() string {
			key, err := seal.Read(state)
			if err != nil {
				return ""
			}
			return seal.Public(key)
		},
	}
}

func networkCommand(what string, stdout io.Writer) error {
	if err := asRoot("network " + what); err != nil {
		return err
	}
	return networkWith(what, localMesh(stateDir), stdout)
}

func networkWith(what string, m *mesh.Mesh, stdout io.Writer) error {
	if what == "rules" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return m.Rules(ctx)
	}
	fingerprint, err := m.Fingerprint()
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, fingerprint)
	return nil
}

func runLogged(name string, args ...string) {
	if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		log.Printf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

func updater(executable string) func(context.Context, string) error {
	return func(ctx context.Context, target string) error {
		_ = os.Remove(update.StatusPath)
		if _, err := update.WriteRequest(update.RequestPath, target, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		output, err := exec.CommandContext(ctx, "systemd-run", "--unit=krynodes-update", "--collect", "--quiet", "--wait", executable, "self-update").CombinedOutput()
		if err == nil {
			return nil
		}
		if status, ok := update.ReadStatus(update.StatusPath, version); ok {
			return errors.New(status.Message)
		}
		if said := strings.TrimSpace(string(output)); said != "" {
			return fmt.Errorf("the update did not run: %s", said)
		}
		return fmt.Errorf("the update did not run: %w", err)
	}
}

func updateFailure() string {
	for range 450 {
		if exec.Command("systemctl", "is-active", "--quiet", "krynodes-update.service").Run() != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if status, ok := update.ReadStatus(update.StatusPath, version); ok {
		return status.Message
	}
	return "the update did not finish; this server still runs " + version
}

func self() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(executable)
}

func installService(stdout io.Writer) error {
	if err := asRoot("install-service"); err != nil {
		return err
	}
	if _, err := config.Load(configPath); err != nil {
		return err
	}
	installed, _ := filepath.EvalSymlinks(binPath)
	if executable, err := self(); err != nil || executable != installed {
		return fmt.Errorf("install-service runs the agent from %s; install it there first", binPath)
	}
	if err := safefile.Write(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", unitName).Run(); err != nil {
		return fmt.Errorf("enable %s: %w", unitName, err)
	}
	if _, err := os.Lstat(sudoLink); os.IsNotExist(err) {
		if err := os.Symlink(binPath, sudoLink); err != nil {
			fmt.Fprintf(os.Stderr, "Could not link %s (%v); run sudo %s instead of sudo kry.\n", sudoLink, err, binPath)
		}
	}
	fmt.Fprintf(stdout, "Installed and started %s.\n", unitName)
	return nil
}

func uninstallService(deleteApps bool, stdout io.Writer) error {
	if err := asRoot("uninstall-service"); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	var problems []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := localMesh(stateDir).Leave(ctx); err != nil {
		problems = append(problems, err.Error())
	}
	said, kept, stayed := stacks.Uninstall(ctx, runCommand, stateDir, deleteApps)
	problems = append(problems, kept...)
	for _, line := range said {
		fmt.Fprintln(stdout, "  "+line)
	}
	if target, err := os.Readlink(sudoLink); err == nil && target == binPath {
		_ = os.Remove(sudoLink)
	}
	for _, path := range removed {
		if path == stateDir && stayed {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			problems = append(problems, fmt.Sprintf("remove %s: %v", path, err))
		}
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if len(problems) > 0 {
		return fmt.Errorf("some parts need a look:\n  %s", strings.Join(problems, "\n  "))
	}
	fmt.Fprintln(stdout, "Krynodes is removed from this server. If it is still in the dashboard, delete it there too.")
	return nil
}

func selfUpdate() error {
	if err := asRoot("self-update"); err != nil {
		return err
	}
	key, err := update.PublicKey()
	if err != nil {
		return err
	}
	executable, err := self()
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
		Client:         secureClient(),
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

func resetTrust(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	reset := flags.Bool("reset", false, "trust only the given passkeys from now on")
	origin := flags.String("origin", "", "your dashboard's origin")
	list := flags.String("trust", "", "the passkeys to trust, as id.alg.key separated by commas")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*reset || flags.NArg() > 0 {
		return errors.New("usage: kry trust --reset --origin <dashboard> --trust <id.alg.key,...>")
	}
	if err := asRoot("trust"); err != nil {
		return err
	}
	next, err := reseed(configPath, stateDir, *origin, tokens(*list))
	if err != nil {
		return err
	}
	_ = exec.Command("systemctl", "try-restart", unitName).Run()
	fmt.Fprintf(stdout, "This server trusts %d passkeys now (version %d).\n", len(next.Core), next.Version)
	return nil
}

func reseed(configPath, state, origin string, tokens []string) (trust.Trust, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return trust.Trust{}, err
	}
	next, err := trust.FirstTrust(cfg.NodeID, origin, tokens)
	if err != nil {
		return trust.Trust{}, err
	}
	if current, err := trust.Load(state); err == nil {
		next.Version = current.Version + 1
	}
	return next, trust.Save(state, next)
}

func secureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
	}}
}
