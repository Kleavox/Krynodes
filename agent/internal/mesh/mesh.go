package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	maxMessage     = 2048
	commandTimeout = 2 * time.Minute
)

var readLimit = 20 * time.Second

type Mesh struct {
	State, Root string
	Executable  string
	Run         network.Runner
	Now         func() time.Time
	Trust       func() trust.Trust
	SealKey     func() string
	Send        func(any) error
	Unseal      func(string) ([]byte, error)
	Left        func()

	mu   sync.Mutex
	left bool
}

func (m *Mesh) keysDir() string {
	return filepath.Join(m.State, "network")
}

func (m *Mesh) Ensure(_ context.Context) error {
	_, err := network.Load(m.keysDir(), true)
	return err
}

func (m *Mesh) Fingerprint() (string, error) {
	keys, err := network.Load(m.keysDir(), false)
	if err != nil {
		return "", errors.New("this server has no network keys; they are made when it enrolls")
	}
	sealKey := m.SealKey()
	if sealKey == "" {
		return "", errors.New("this server has no seal key; it is made when it enrolls")
	}
	return network.Fingerprint(keys.Public, keys.Signer, sealKey), nil
}

func notReady(found network.Inspect) string {
	switch {
	case !found.Kernel.OK && found.Kernel.Reason != nil && *found.Kernel.Reason == "container":
		return "This server is a container that cannot load WireGuard; its host has to provide it."
	case !found.Kernel.OK:
		return "This server's kernel has no WireGuard."
	case !found.Iptables:
		return "This server has no iptables and ip6tables, which the private network needs."
	case found.Port == nil:
		return "No UDP port from 51820 to 51919 is free on this server."
	}
	return ""
}

func (m *Mesh) tables(ctx context.Context) string {
	for _, tool := range []string{"iptables", "ip6tables"} {
		if output, ok := m.output(ctx, tool, "-w", "-S"); !ok {
			said, _, _ := strings.Cut(strings.TrimSpace(output), "\n")
			return clip("This server's "+tool+" does not work: "+said, 300)
		}
	}
	return ""
}

func (m *Mesh) read(ctx context.Context) (network.Inspect, string, error) {
	ctx, cancel := context.WithTimeout(ctx, readLimit)
	defer cancel()
	found := network.Read(ctx, m.Root, m.Run)
	reason := notReady(found)
	if reason == "" {
		reason = m.tables(ctx)
		found.Iptables = reason == ""
	}
	if ctx.Err() != nil {
		return found, "", fmt.Errorf("this server did not finish checking itself within %s", readLimit)
	}
	return found, reason, nil
}

func clip(text string, most int) string {
	if len(text) <= most {
		return text
	}
	return strings.ToValidUTF8(text[:most], "")
}

func (m *Mesh) Hello(ctx context.Context) *reporter.NetworkHello {
	keys, err := network.Load(m.keysDir(), false)
	if err != nil {
		return nil
	}
	hello := &reporter.NetworkHello{Key: keys.Public, Signer: keys.Signer}
	current, err := m.load()
	reason := ""
	if err != nil {
		reason = clip("This server cannot read its network record: "+err.Error(), 300)
	} else if _, reason, err = m.read(ctx); err != nil {
		reason = "This server did not finish checking itself in time; it checks again when it reconnects."
	}
	hello.Version, hello.Ready = current.Applied.Version, reason == ""
	if reason != "" {
		hello.Reason = &reason
	}
	return hello
}

func (m *Mesh) Handlers() map[string]daemon.Handler {
	return map[string]daemon.Handler{
		"network/inspect":   m.handle(m.inspect),
		"network/probe":     m.handle(m.probe),
		"network/test":      m.handle(m.linkTest),
		"network/prepare":   m.handle(m.prepare),
		"network/unprepare": m.handle(m.unprepare),
		"network/rekey":     m.handle(m.rekey),
		"network/drop":      m.handle(m.drop),
	}
}

func (m *Mesh) handle(run func(context.Context, map[string]string) (string, error)) daemon.Handler {
	return func(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
		if cmd.Name != network.Interface {
			return "", fmt.Errorf("network commands name %s", network.Interface)
		}
		args := cmd.Args
		if args == nil {
			args = map[string]string{}
		}
		return run(ctx, args)
	}
}

func none(args map[string]string, verb string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments", verb)
	}
	return nil
}

func answer(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxMessage {
		return "", errors.New("the answer does not fit in one message")
	}
	return string(encoded), nil
}

func (m *Mesh) self() (string, error) {
	node := m.Trust().NodeID
	if node == "" {
		return "", errors.New("this server has no trust yet")
	}
	return node, nil
}

func (m *Mesh) command(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, _, err := m.Run(ctx, name, args...)
	if text := strings.TrimSpace(string(output)); err != nil && text != "" {
		return fmt.Errorf("%w: %s", err, text[:min(len(text), 400)])
	}
	return err
}

func (m *Mesh) output(ctx context.Context, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, _, err := m.Run(ctx, name, args...)
	return string(output), err == nil
}
