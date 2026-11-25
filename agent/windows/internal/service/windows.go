//go:build windows

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/update"
	"github.com/Kleavox/krynodes/agent/windows/internal/bundle"
	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
	"github.com/Kleavox/krynodes/agent/windows/internal/store"
	"github.com/Kleavox/krynodes/agent/windows/internal/tunnel"
)

const (
	serviceName = "Krynodes"
	runKey      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	notReady    = 2
	maxDownload = 64 << 20
)

type system struct{}

func (system) Source() (string, error) {
	return os.Executable()
}

func (system) Program() (string, error) {
	return bundle.Program()
}

func (system) StopService() error {
	return stopService()
}

func (system) Unpack(dir string) error {
	return bundle.Unpack(dir)
}

func (system) Folder(dir string) error {
	return store.ProgramFolder(dir)
}

func (system) Write(path string, data []byte) error {
	return store.ProgramFile(path, data)
}

func (system) StartService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func stopService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Control(svc.Stop)
	if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return nil
	}
	if err != nil {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); status.State != svc.Stopped; {
		if time.Now().After(deadline) {
			return errors.New("the Krynodes service did not stop in 30 seconds")
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = service.Query(); err != nil {
			return err
		}
	}
	return nil
}

func (system) Register(executable string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	config := mgr.Config{
		DisplayName: "Krynodes",
		Description: "Keeps this laptop on the Krynodes private network.",
		StartType:   mgr.StartAutomatic,
	}
	service, err := manager.OpenService(serviceName)
	if err == nil {
		current, err := service.Config()
		if err == nil {
			current.BinaryPathName = syscall.EscapeArg(executable) + " service"
			current.DisplayName, current.Description, current.StartType = config.DisplayName, config.Description, config.StartType
			current.ServiceStartName = "LocalSystem"
			err = service.UpdateConfig(current)
		}
		if err != nil {
			service.Close()
			return err
		}
	} else if service, err = manager.CreateService(serviceName, executable, config, "service"); err != nil {
		return err
	}
	defer service.Close()
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400); err != nil {
		return err
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(false); err != nil {
		return err
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func (system) Tray(executable string) error {
	return startWithWindows(executable, true)
}

func (c control) startTray(session uint32) error {
	return userSession{
		Processes: processes,
		Token:     userToken,
		Elevated:  func(token uintptr) bool { return windows.Token(token).IsElevated() },
		Start: func(token uintptr, command string) error {
			return startAs(windows.Token(token), c.executable, command)
		},
		Close: func(token uintptr) { windows.Token(token).Close() },
	}.startTray(c.executable, session)
}

func (c control) trayFor(session uint32) {
	if !trayStarts() {
		return
	}
	if err := c.startTray(session); err != nil && !errors.Is(err, errNoUser) {
		log.Print(err)
	}
}

func processes() ([]process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var list []process
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		var session uint32
		if windows.ProcessIdToSessionId(entry.ProcessID, &session) != nil {
			continue
		}
		list = append(list, process{Session: session, Name: windows.UTF16ToString(entry.ExeFile[:])})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return list, nil
}

func userToken(session uint32) (uintptr, error) {
	var token windows.Token
	err := windows.WTSQueryUserToken(session, &token)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		return 0, errNoUser
	}
	return uintptr(token), err
}

func startAs(token windows.Token, executable, command string) error {
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	line, err := windows.UTF16FromString(command)
	if err != nil {
		return err
	}
	folder, err := windows.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	var environment *uint16
	if err := windows.CreateEnvironmentBlock(&environment, token, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(environment)
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var info windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, application, &line[0], nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, environment, folder, &startup, &info); err != nil {
		return err
	}
	windows.CloseHandle(info.Thread)
	windows.CloseHandle(info.Process)
	return nil
}

func startWithWindows(executable string, on bool) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !on {
		if err := key.DeleteValue(serviceName); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		return nil
	}
	return key.SetStringValue(serviceName, `"`+executable+`" tray`)
}

func trayStarts() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	_, _, err = key.GetStringValue(serviceName)
	return err == nil
}

type control struct {
	*Service
	executable string
	version    string
	updating   *atomic.Bool
	restart    chan struct{}
}

func (c control) Status(seen uint64) pipe.Status {
	status := c.Service.Status(seen)
	status.FirewallOff = status.Connected && status.Joined && tunnel.FirewallOff()
	status.StartWithWindows = trayStarts()
	status.Version = c.version
	return status
}

func (c control) Settings(settings pipe.Settings) error {
	if settings.StartWithWindows != nil {
		if err := startWithWindows(c.executable, *settings.StartWithWindows); err != nil {
			log.Printf("start the tray with Windows: %v", err)
			return errors.New("Start with Windows could not be changed. The service log says why.")
		}
	}
	if settings.NotifyOffline != nil {
		return c.NotifyOffline(*settings.NotifyOffline)
	}
	return nil
}

func (c control) tell(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.say(line)
}

func (c control) Update() error {
	if !c.updating.CompareAndSwap(false, true) {
		return errors.New("The agent is already updating.")
	}
	go func() {
		defer c.updating.Store(false)
		next, err := c.release().Update(context.Background())
		switch {
		case errors.Is(err, ErrUpToDate):
			c.tell("This agent is up to date.")
		case err != nil:
			log.Printf("update the agent: %v", err)
			c.tell("The agent could not update. The service log says why.")
		default:
			log.Printf("updated the agent to %s; restarting", next)
			c.mu.Lock()
			line := "Krynodes " + next + " is installed and restarts in a few seconds."
			if c.exit != "" {
				line += " Pick the exit node again."
			}
			c.say(line)
			c.mu.Unlock()
			time.Sleep(5 * time.Second)
			watcher := exec.Command(filepath.Join(filepath.Dir(c.executable), oldName), "after-update", next, c.executable)
			watcher.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
			if err := watcher.Start(); err == nil {
				_ = watcher.Process.Release()
				return
			}
			log.Printf("start the previous agent to watch the update: %v; restarting without it", err)
			select {
			case c.restart <- struct{}{}:
			default:
			}
		}
	}()
	return nil
}

func (c control) offer(ctx context.Context) {
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 6 * time.Hour
		latest, err := c.release().Latest(ctx)
		if err != nil {
			log.Printf("check for a newer agent: %v", err)
			continue
		}
		c.Offer(latest, c.version)
	}
}

func AfterUpdate(args []string, version string) error {
	if len(args) != 2 {
		return errors.New("Update Agent runs after-update; it is not run by hand")
	}
	watch := Watch{
		Executable: args[1],
		Previous:   version,
		Stop:       stopService,
		Start:      system{}.StartService,
		PID:        servicePID,
		Sleep:      time.Sleep,
		Note: func(line string) {
			if secrets, err := openStore(); err == nil {
				_ = secrets.Write(filepath.Join(secrets.Dir, updateNote), []byte(line))
			}
		},
	}
	return watch.Run(args[0])
}

func servicePID() (uint32, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return 0, err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil || status.State != svc.Running {
		return 0, err
	}
	return status.ProcessId, nil
}

func (c control) release() Release {
	key, err := update.PublicKey()
	if err != nil {
		log.Printf("the release key: %v", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	transport.ResponseHeaderTimeout = time.Minute
	return Release{
		Current:    c.version,
		Key:        key,
		Executable: c.executable,
		Write:      store.ProgramFile,
		Latest: func(ctx context.Context) (string, error) {
			client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(update.DefaultBase, "/download")+"/latest", nil)
			if err != nil {
				return "", err
			}
			response, err := client.Do(request)
			if err != nil {
				return "", fmt.Errorf("find the newest release: %w", err)
			}
			response.Body.Close()
			latest, ok := LatestFrom(response.Header.Get("Location"))
			if !ok {
				return "", fmt.Errorf("find the newest release: HTTP %d to %q", response.StatusCode, response.Header.Get("Location"))
			}
			return latest, nil
		},
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			client := &http.Client{Transport: transport, Timeout: 15 * time.Minute}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			response, err := client.Do(request)
			if err != nil {
				return nil, fmt.Errorf("download %s: %w", url, err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
			}
			data, err := io.ReadAll(io.LimitReader(response.Body, maxDownload+1))
			if err != nil {
				return nil, fmt.Errorf("download %s: %w", url, err)
			}
			if len(data) > maxDownload {
				return nil, fmt.Errorf("download %s: larger than 64 MiB", url)
			}
			return data, nil
		},
		Run: func(path string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, path, "version").Output()
			return string(output), err
		},
	}
}

func serve(ctx context.Context, backend pipe.Backend) {
	said := ""
	for {
		err := pipe.Serve(ctx, backend)
		if ctx.Err() != nil {
			return
		}
		if line := fmt.Sprintf("the tray's pipe: %v", err); line != said {
			log.Print(line)
			said = line
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func openStore() (store.Store, error) {
	dir, err := store.Dir()
	if err != nil {
		return store.Store{}, err
	}
	return store.Open(dir)
}

func InstallCommand(args []string, version string, out io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	code := flags.String("code", "", "the code from Add Laptop")
	origin := flags.String("origin", "", "your dashboard's origin")
	endpoint := flags.String("endpoint", "", "the agent origin, when it is not the dashboard's")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*code) == "" || *origin == "" {
		return errors.New("use install --code <code> --origin <url>")
	}
	if *endpoint == "" {
		*endpoint = *origin
	}
	if err := bundle.Missing(); err != nil {
		return err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run install as Administrator")
	}
	secrets, err := openStore()
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return Install(ctx, &http.Client{Transport: transport}, secrets.Dir, secrets, system{}, Enrollment{Code: strings.TrimSpace(*code), Origin: *origin, Endpoint: *endpoint, Version: version, Kernel: kernel()}, out)
}

type handler struct {
	version string
}

func (h handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	secrets, err := openStore()
	if err != nil {
		line := "the Krynodes service cannot open its folder: " + err.Error()
		log.Print(line)
		if events, err := eventlog.Open(serviceName); err == nil {
			events.Error(1, line)
			events.Close()
		}
		return true, notReady
	}
	log.SetOutput(secrets.Log("service.log"))
	executable, err := os.Executable()
	if err != nil {
		log.Printf("the tray's pipe stays closed and updates are off: %v", err)
	} else if err := bundle.Unpack(filepath.Dir(executable)); err != nil {
		log.Printf("place wintun.dll and the licences beside the agent: %v", err)
	}
	service := &Service{Dir: secrets.Dir, Secrets: secrets, Now: time.Now, Kernel: kernel()}
	notePath := filepath.Join(secrets.Dir, updateNote)
	if line, err := safefile.Read(notePath, 4096); err == nil {
		_ = os.Remove(notePath)
		service.mu.Lock()
		service.say(string(line))
		service.mu.Unlock()
	}
	record, _ := service.read()
	if err := tunnel.RemoveNRPT(); err != nil {
		log.Printf("clear a leftover exit DNS rule: %v", err)
	}
	adapter := tunnel.New(record.NodeID)
	defer adapter.Close()
	service.Apply = func(wanted Wanted) error {
		return adapter.Apply(configOf(wanted))
	}
	service.Ping = func(address string) (time.Duration, bool) {
		return tunnel.Ping(address, 800*time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go refresh(ctx, adapter)
	restart := make(chan struct{}, 1)
	backend := control{Service: service, executable: executable, version: h.version, updating: &atomic.Bool{}, restart: restart}
	if executable != "" {
		go serve(ctx, backend)
		go backend.offer(ctx)
	}
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx, h.version) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	if executable != "" {
		go backend.trayFor(windows.WTSGetActiveConsoleSessionId())
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(time.Minute):
				Tidy(executable)
			}
		}()
	}
	for {
		select {
		case <-restart:
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			adapter.Close()
			os.Exit(1)
		case err := <-done:
			if err != nil {
				log.Printf("the Krynodes service stopped and stays stopped: %v", err)
				return true, notReady
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.SessionChange:
				if session, logon := loggedOn(request); logon && executable != "" {
					go backend.trayFor(session)
				}
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
				}
				return false, 0
			}
		}
	}
}

var consoleSession = windows.WTSGetActiveConsoleSessionId

func loggedOn(request svc.ChangeRequest) (uint32, bool) {
	if request.Cmd != svc.SessionChange || request.EventType != windows.WTS_SESSION_LOGON {
		return 0, false
	}
	return consoleSession(), true
}

func kernel() string {
	version := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
}

func configOf(wanted Wanted) tunnel.Config {
	config := tunnel.Config{Key: wanted.Key, Address: wanted.Address, MTU: wanted.MTU, DNS: wanted.DNS, Exit: wanted.Exit != "", Local: wanted.Local}
	for _, peer := range wanted.Peers {
		config.Peers = append(config.Peers, tunnel.Peer{Key: peer.Key, PresharedKey: peer.PresharedKey, Endpoint: peer.Endpoint, Pin: peer.Pin, Relay: peer.Relay, AllowedIPs: peer.AllowedIPs, Keepalive: peer.PersistentKeepalive})
	}
	return config
}

func refresh(ctx context.Context, adapter *tunnel.Tunnel) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	said := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		line := ""
		if err := adapter.Refresh(); err != nil {
			line = err.Error()
		}
		if line != said && line != "" {
			log.Printf("tunnel: %s", line)
		}
		said = line
	}
}

func RunService(version string) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !inService {
		return errors.New("Windows starts the service; add this laptop with install")
	}
	return svc.Run(serviceName, handler{version: version})
}
