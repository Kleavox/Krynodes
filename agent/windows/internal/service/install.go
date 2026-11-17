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
	"runtime"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

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
}

type Enrollment struct {
	Code     string
	Origin   string
	Endpoint string
	Version  string
}

type laptopKeys struct {
	Key     string `json:"key"`
	Signer  string `json:"signer"`
	Port    int    `json:"port"`
	SealKey string `json:"sealKey"`
}

func Install(ctx context.Context, client *http.Client, dir string, secrets Secrets, system System, enrollment Enrollment) error {
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
	if _, err := secrets.Get(tokenSecret); errors.Is(err, os.ErrNotExist) {
		if err := enroll(ctx, client, dir, secrets, enrollment); err != nil {
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
	return nil
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

func enroll(ctx context.Context, client *http.Client, dir string, secrets Secrets, enrollment Enrollment) error {
	keys, sealing, err := newKeys(secrets)
	if err != nil {
		return fmt.Errorf("make the laptop's keys: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		reporter.Host
		Laptop laptopKeys `json:"laptop"`
	}{
		Host:   reporter.Host{Hostname: hostname, OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, AgentVersion: enrollment.Version},
		Laptop: laptopKeys{Key: keys.Public, Signer: keys.Signer, Port: network.FirstPort, SealKey: seal.Public(sealing)},
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(enrollment.Endpoint, "/")+"/api/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+enrollment.Code)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "kry-agent/"+enrollment.Version)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("reach Krynodes: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return errors.New("the code is not valid; it works once and for 10 minutes, so make a new one with Add Laptop")
	case response.StatusCode < 200 || response.StatusCode > 299:
		return fmt.Errorf("Krynodes refused the code with HTTP %d", response.StatusCode)
	}
	var answer struct {
		reporter.Enrollment
		Trust []string `json:"trust"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.NodeID == "" || answer.Token == "" {
		return errors.New("Krynodes answered the code with something else")
	}
	if len(answer.Trust) == 0 {
		return errors.New("Krynodes sent no trusted passkeys, so this laptop could not check anything signed; add a passkey in the dashboard, make a new code and run install again")
	}
	first, err := trust.ParseTrustArgs(enrollment.Origin, answer.Trust, true, "")
	if err != nil {
		return err
	}
	first.NodeID = answer.NodeID
	service := Service{Dir: dir, Secrets: secrets}
	if err := service.keep(trustFile, first); err != nil {
		return err
	}
	if err := service.save(state{Endpoint: enrollment.Endpoint, NodeID: answer.NodeID, Interval: answer.IntervalSeconds}); err != nil {
		return err
	}
	return secrets.Put(tokenSecret, []byte(answer.Token))
}
