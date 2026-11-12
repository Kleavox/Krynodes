package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
)

const (
	heldFile     = "held.json"
	endpointFile = "endpoint"
	heldEvery    = 4 * time.Minute
)

type heldState struct {
	Held bool      `json:"held"`
	At   time.Time `json:"at"`
}

func WorkerHeld(stateDir, configPath, version string, client *http.Client) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		cfg, err := config.Load(configPath)
		if err != nil {
			return false, err
		}
		endpoint := ""
		if pinned, err := os.ReadFile(filepath.Join(stateDir, endpointFile)); err == nil {
			endpoint = strings.TrimSpace(string(pinned))
		}
		if endpoint == "" {
			endpoint = cfg.Endpoint
			if err := writeWhole(stateDir, endpointFile, []byte(endpoint+"\n"), 0o640); err != nil {
				return false, err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/api/agent/held", nil)
		if err != nil {
			return false, err
		}
		request.Header.Set("Authorization", "Bearer "+cfg.Token)
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "kry-agent/"+version)
		response, err := client.Do(request)
		if err != nil {
			return false, err
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusOK:
			var answer struct {
				Held bool `json:"held"`
			}
			if err := json.NewDecoder(io.LimitReader(response.Body, 1<<10)).Decode(&answer); err != nil {
				return false, err
			}
			return answer.Held, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return true, nil
		}
		return false, fmt.Errorf("Krynodes answered %d", response.StatusCode)
	}
}

func (e Executor) held(ctx context.Context) bool {
	if e.quarantined() {
		return true
	}
	if e.Held == nil {
		return false
	}
	state, _ := readState[heldState](e.StateDir, heldFile)
	if !state.At.IsZero() && e.Now().Sub(state.At) < heldEvery {
		return state.Held
	}
	held, err := e.Held(ctx)
	if err != nil {
		log.Printf("asking Krynodes whether this server is held: %v", err)
		return state.Held
	}
	if err := writeJSON(e.StateDir, heldFile, heldState{Held: held, At: e.Now()}, 0o640); err != nil {
		log.Printf("held: %v", err)
	}
	return held
}

func (e Executor) heldRecorded() bool {
	state, _ := readState[heldState](e.StateDir, heldFile)
	return e.quarantined() || state.Held
}
