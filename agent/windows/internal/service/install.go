package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

var plainName = regexp.MustCompile(`^[\p{L}\p{N}-]{1,64}$`)

type System interface {
	Source() (string, error)
	Program() (string, error)
	StopService() error
	StartService() error
	Unpack(dir string) error
	Folder(dir string) error
	Write(path string, data []byte) error
	Register(executable string) error
	Tray(executable string) error
	Shortcut(executable string) error
}

type process struct {
	Session uint32
	Name    string
}

type userSession struct {
	Processes func() ([]process, error)
	Token     func(session uint32) (uintptr, error)
	Elevated  func(token uintptr) bool
	Start     func(token uintptr, command string) error
	Close     func(token uintptr)
}

const noSession = ^uint32(0)

var (
	errNoUser   = errors.New("no one is signed in at this laptop")
	errElevated = errors.New("the user's token is elevated, and the tray is never started elevated")
)

func (s userSession) startTray(executable string, session uint32) error {
	if session == noSession {
		return fmt.Errorf("start the tray: find the signed-in user: %w", errNoUser)
	}
	running, err := s.Processes()
	if err != nil {
		return fmt.Errorf("start the tray: find the signed-in user: %w", err)
	}
	for _, found := range running {
		if found.Session == session && strings.EqualFold(found.Name, executable[strings.LastIndexAny(executable, `\/`)+1:]) {
			return nil
		}
	}
	token, err := s.Token(session)
	if err != nil {
		return fmt.Errorf("start the tray: take the user's token: %w", err)
	}
	defer s.Close(token)
	if s.Elevated(token) {
		return fmt.Errorf("start the tray: take the user's token: %w", errElevated)
	}
	if err := s.Start(token, `"`+executable+`" tray`); err != nil {
		return fmt.Errorf("start the tray: start the program: %w", err)
	}
	return nil
}

type Enrollment struct {
	Code     string
	Origin   string
	Endpoint string
	Version  string
	Kernel   string
}

func Install(ctx context.Context, client *http.Client, dir string, secrets Secrets, system System, enrollment Enrollment, out io.Writer) error {
	for _, origin := range []string{enrollment.Origin, enrollment.Endpoint} {
		if err := checkOrigin(origin); err != nil {
			return err
		}
	}
	token, err := secrets.Get(tokenSecret)
	enrolled := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read the stored agent token: %w", err)
	}
	renew := false
	if enrolled && enrollment.Code != "" {
		stored, err := (&Service{Dir: dir}).read()
		if err != nil || checkOrigin(stored.Endpoint) != nil {
			return errors.New("this laptop is already enrolled, but its saved settings could not be read; run uninstall first to enroll it again with a new code")
		}
		if renew, err = tokenIsDead(ctx, client, stored.Endpoint, enrollment.Version, string(token)); err != nil {
			return err
		}
	}
	executable, stopped, err := place(system)
	fail := func(err error) error {
		if !stopped {
			return err
		}
		if started := system.StartService(); started != nil {
			return fmt.Errorf("%w; the Krynodes service could not start again: %v", err, started)
		}
		return err
	}
	if err != nil {
		return fail(fmt.Errorf("copy the agent: %w", err))
	}
	approve := "The network fingerprint is in the tray menu.\n"
	if enrolled && enrollment.Code != "" && !renew {
		approve = "This laptop is already enrolled, so a new code is not needed. Run uninstall first to enroll it again with a new code.\n" + approve
	}
	if !enrolled || renew {
		if renew && !stopped {
			stopped = true
			if err := system.StopService(); err != nil {
				return fail(err)
			}
		}
		if approve, err = enroll(ctx, client, dir, secrets, enrollment); err != nil {
			return fail(err)
		}
	}
	if err := system.Tray(executable); err != nil {
		return fail(fmt.Errorf("start the tray with Windows: %w; run install again to finish", err))
	}
	if err := system.Shortcut(executable); err != nil {
		return fail(fmt.Errorf("make the Start menu entry: %w; run install again to finish", err))
	}
	if err := system.Register(executable); err != nil {
		return fail(fmt.Errorf("start the Krynodes service: %w; run install again to finish", err))
	}
	_, err = fmt.Fprint(out, "Krynodes is installed.\n"+approve)
	return err
}

func tokenIsDead(ctx context.Context, client *http.Client, endpoint, version, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/api/agent/stream", nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "kry-agent/"+version)
	asking := *client
	asking.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := asking.Do(request)
	if err != nil {
		return false, fmt.Errorf("reach Krynodes: %w", err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		return false, fmt.Errorf("reach Krynodes: %w", err)
	}
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return true, nil
	case http.StatusUpgradeRequired:
		return false, nil
	}
	return false, fmt.Errorf("Krynodes answered HTTP %d when this laptop's token was checked", response.StatusCode)
}

func place(system System) (string, bool, error) {
	source, err := system.Source()
	if err != nil {
		return "", false, err
	}
	target, err := system.Program()
	if err != nil {
		return "", false, err
	}
	dir := filepath.Dir(target)
	if strings.EqualFold(filepath.Clean(source), filepath.Clean(target)) {
		return target, false, system.Unpack(dir)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", false, err
	}
	if current, err := os.ReadFile(target); err == nil && bytes.Equal(current, data) {
		return target, false, system.Unpack(dir)
	}
	if err := system.StopService(); err != nil {
		return "", true, err
	}
	if err := system.Folder(dir); err != nil {
		return "", true, err
	}
	if err := swapIn(system.Write, target, data, nil); err != nil {
		return "", true, err
	}
	return target, true, system.Unpack(dir)
}

func checkOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || strings.Trim(parsed.Path, "/") != "" || parsed.RawQuery != "" || parsed.User != nil {
		return fmt.Errorf("%q is not an origin", origin)
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	switch {
	case parsed.Scheme == "https":
		return nil
	case parsed.Scheme == "http" && (host == "localhost" || (address != nil && address.IsLoopback())):
		return nil
	}
	return fmt.Errorf("%q must start with https://", origin)
}

func enroll(ctx context.Context, client *http.Client, dir string, secrets Secrets, enrollment Enrollment) (string, error) {
	fresh, err := generateKeys()
	if err != nil {
		return "", fmt.Errorf("make the laptop's keys: %w", err)
	}
	keys := fresh.keys
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	sealKey := seal.Public(fresh.sealing)
	body, err := json.Marshal(map[string]any{
		"hostname": known(hostname), "os": runtime.GOOS, "arch": runtime.GOARCH, "kernel": known(enrollment.Kernel), "version": enrollment.Version,
		"kind": "laptop", "key": keys.Public, "signer": keys.Signer, "port": network.FirstPort, "sealKey": sealKey,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(enrollment.Endpoint, "/")+"/api/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+enrollment.Code)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "kry-agent/"+enrollment.Version)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("reach Krynodes: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return "", errors.New("the code is not valid; it works once and for 10 minutes, so make a new one with Add Laptop")
	case response.StatusCode < 200 || response.StatusCode > 299:
		return "", fmt.Errorf("Krynodes refused the code with HTTP %d", response.StatusCode)
	}
	var answer struct {
		NodeID string   `json:"nodeId"`
		Name   string   `json:"name"`
		Token  string   `json:"token"`
		Trust  []string `json:"trust"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.NodeID == "" || answer.Token == "" {
		return "", errors.New("Krynodes answered the code with something else")
	}
	if len(answer.Trust) == 0 {
		return "", errors.New("Krynodes sent no trusted passkeys, so this laptop could not check anything signed; add a passkey in the dashboard, make a new code and run install again")
	}
	first, err := trust.FirstTrust(answer.NodeID, enrollment.Origin, answer.Trust)
	if err != nil {
		return "", err
	}
	if err := fresh.store(secrets); err != nil {
		return "", fmt.Errorf("keep the laptop's keys: %w", err)
	}
	service := Service{Dir: dir, Secrets: secrets}
	if err := service.keep(trustFile, first); err != nil {
		return "", err
	}
	if err := service.save(state{Endpoint: enrollment.Endpoint, NodeID: answer.NodeID}); err != nil {
		return "", err
	}
	if err := secrets.Put(tokenSecret, []byte(answer.Token)); err != nil {
		return "", err
	}
	name := "this laptop"
	if plainName.MatchString(answer.Name) {
		name = answer.Name
	}
	return fmt.Sprintf("Network fingerprint: %s\nApprove %s on the Network page of your dashboard.\n", network.Fingerprint(keys.Public, keys.Signer, sealKey), name), nil
}
