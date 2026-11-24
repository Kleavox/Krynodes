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
	StartTray(executable string) error
}

type shellProcess struct {
	ID      uint32
	Session uint32
	Name    string
}

type shellUser struct {
	Session   func() (uint32, error)
	Processes func() ([]shellProcess, error)
	Token     func(id uint32) (uintptr, error)
	Elevated  func(token uintptr) bool
	Start     func(token uintptr, command string) error
	Close     func(token uintptr)
}

var (
	errNoShell       = errors.New("Explorer is not running in this session")
	errElevatedShell = errors.New("Explorer runs elevated in this session, and the tray is never started elevated")
)

func (s shellUser) startTray(executable string) error {
	session, err := s.Session()
	if err != nil {
		return err
	}
	processes, err := s.Processes()
	if err != nil {
		return err
	}
	missing := errNoShell
	for _, process := range processes {
		if process.Session != session || !strings.EqualFold(process.Name, "explorer.exe") {
			continue
		}
		token, err := s.Token(process.ID)
		if err != nil {
			return err
		}
		if s.Elevated(token) {
			s.Close(token)
			missing = errElevatedShell
			continue
		}
		defer s.Close(token)
		return s.Start(token, `"`+executable+`" tray`)
	}
	return missing
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
	if _, err := secrets.Get(tokenSecret); errors.Is(err, os.ErrNotExist) {
		if approve, err = enroll(ctx, client, dir, secrets, enrollment); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(fmt.Errorf("read the stored agent token: %w", err))
	}
	if err := system.Register(executable); err != nil {
		return fail(fmt.Errorf("start the Krynodes service: %w; run install again to finish", err))
	}
	if err := system.Tray(executable); err != nil {
		return fmt.Errorf("start the tray with Windows: %w; run install again to finish", err)
	}
	if err := system.StartTray(executable); err != nil {
		approve += fmt.Sprintf("The tray could not start now (%v); it starts the next time you sign in.\n", err)
	}
	_, err = fmt.Fprint(out, "Krynodes is installed.\n"+approve)
	return err
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
	keys, sealing, err := newKeys(secrets)
	if err != nil {
		return "", fmt.Errorf("make the laptop's keys: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	sealKey := seal.Public(sealing)
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
