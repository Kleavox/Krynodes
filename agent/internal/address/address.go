package address

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Prober struct {
	Endpoint string
	Token    string
	Version  string
	links    func() []link
}

type probeBody struct {
	Interfaces []Interface `json:"interfaces,omitempty"`
}

var networks = []string{"tcp4", "tcp6"}

func clientFor(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig:       reporter.TLSConfig(),
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
	}
}

func (p Prober) ask(ctx context.Context, network string, body []byte) (string, error) {
	address, err := p.send(ctx, network, body)
	var refused *reporter.ResponseError
	if errors.As(err, &refused) && (refused.Status == http.StatusNotFound || refused.Status == http.StatusMethodNotAllowed) {
		return p.send(ctx, network, nil)
	}
	return address, err
}

func (p Prober) send(ctx context.Context, network string, body []byte) (string, error) {
	method, payload := http.MethodGet, io.Reader(nil)
	if body != nil {
		method, payload = http.MethodPost, bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.Endpoint, "/")+"/api/agent/address", payload)
	if err != nil {
		return "", err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+p.Token)
	request.Header.Set("User-Agent", "kry-agent/"+p.Version)
	response, err := clientFor(network).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", &reporter.ResponseError{Status: response.StatusCode}
	}
	var answer struct {
		Address *string `json:"address"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer); err != nil {
		return "", err
	}
	if answer.Address == nil {
		return "", nil
	}
	return *answer.Address, nil
}

func (p Prober) Probe(ctx context.Context) map[string]string {
	read := p.links
	if read == nil {
		read = readLinks
	}
	body, err := json.Marshal(probeBody{Interfaces: usable(read())})
	if err != nil {
		body = []byte("{}")
	}
	found := map[string]string{}
	for _, network := range networks {
		address, err := p.ask(ctx, network, body)
		if err == nil && address != "" {
			found[network] = address
		}
	}
	return found
}

func (p Prober) Watch(ctx context.Context, every time.Duration) {
	for {
		found := p.Probe(ctx)
		if len(found) == 0 {
			log.Printf("address check: Krynodes could not see this server's address")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
