package address

import (
	"context"
	"encoding/json"
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

func (p Prober) ask(ctx context.Context, network string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.Endpoint, "/")+"/api/agent/address", nil)
	if err != nil {
		return "", err
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
	found := map[string]string{}
	for _, network := range networks {
		address, err := p.ask(ctx, network)
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
