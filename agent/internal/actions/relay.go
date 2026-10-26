package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	RequestDir    = "/var/lib/kry/actions"
	StateDir      = "/var/lib/kry-exec"
	refreshMarker = "refresh"
	maxReported   = 10
	maxResultText = 65536
	reportBudget  = 512 << 10
	maxProgress   = 10
	progressGap   = 5 * time.Second
)

type sentStep struct {
	step reporter.Progress
	at   time.Time
}

type Poster interface {
	PostActions(context.Context, reporter.ActionsReport) (reporter.ActionsResponse, error)
}

type Relay struct {
	RequestDir string
	StateDir   string
	NodeID     string
	Server     Poster
	Now        func() time.Time

	mu        sync.Mutex
	acked     string
	sentList  string
	refreshAt time.Time
	failures  int
	retryAt   time.Time
	problem   string
	steps     map[string]sentStep
	queued    map[string]time.Time
}

func backoff(failures int) time.Duration {
	return min(5*time.Second<<min(failures-1, 7), 10*time.Minute)
}

func (r *Relay) note(err error) {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if message := err.Error(); message != r.problem {
		r.problem = message
		log.Printf("read service action state: %v", err)
	}
}

func (r *Relay) Enqueue(requests []Request) error {
	if err := os.MkdirAll(r.RequestDir, 0o750); err != nil {
		return err
	}
	for _, request := range requests {
		if !requestName.MatchString(request.ID+".json") || !ValidTarget(request.Kind, request.Name) {
			return fmt.Errorf("refusing malformed action %q", request.ID)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		temporary := filepath.Join(r.RequestDir, "."+request.ID+".tmp")
		if err := os.WriteFile(temporary, encoded, 0o640); err != nil {
			return err
		}
		if err := os.Rename(temporary, filepath.Join(r.RequestDir, request.ID+".json")); err != nil {
			return err
		}
	}
	return nil
}

func (r *Relay) Refresh() error {
	r.mu.Lock()
	r.refreshAt = r.Now()
	r.mu.Unlock()
	if err := os.MkdirAll(r.RequestDir, 0o750); err != nil {
		return err
	}
	marker := filepath.Join(r.RequestDir, refreshMarker)
	if err := os.WriteFile(marker, nil, 0o640); err != nil {
		return err
	}
	return os.Remove(marker)
}

func (r *Relay) Poll(ctx context.Context) error {
	r.mu.Lock()
	waiting := r.Now().Before(r.retryAt)
	r.mu.Unlock()
	if waiting {
		return nil
	}
	results := r.readResults()
	steps := r.readProgress()
	var inventory *Inventory
	var current Inventory
	if err := readJSON(filepath.Join(r.StateDir, "inventory.json"), &current); err == nil {
		inventory = &current
	} else {
		r.note(err)
	}
	r.mu.Lock()
	acked, refreshAt, sentList := r.acked, r.refreshAt, r.sentList
	r.mu.Unlock()

	report := reporter.ActionsReport{NodeID: r.NodeID, Results: results, Progress: steps}
	refreshed := false
	listing := ""
	if inventory != nil {
		changed := inventory.Hash != acked
		taken, err := time.Parse(time.RFC3339Nano, inventory.TakenAt)
		refreshed = err == nil && !refreshAt.IsZero() && !taken.Before(refreshAt)
		if changed || refreshed {
			report.Inventory = &reporter.InventoryReport{Hash: inventory.Hash}
			if changed {
				services, stacks, trust := inventory.Services, inventory.Stacks, inventory.Trust
				report.Inventory.Docker = inventory.Docker
				report.Inventory.SealKey = inventory.SealKey
				report.Inventory.Security = inventory.Security
				report.Inventory.Vault = &reporter.VaultSlot{Report: inventory.Vault}
				removed := inventory.Removed
				report.Inventory.Removed = &removed
				report.Inventory.Services = &services
				report.Inventory.Stacks = &stacks
				report.Inventory.Trust = &trust
				report.Inventory.Tailscale = inventory.Tailscale
				report.Inventory.Network = inventory.Network
				if inventory.Packages != nil && inventory.PackagesHash != sentList {
					report.Inventory.Packages = inventory.Packages
					listing = inventory.PackagesHash
				}
			}
		}
	}
	if len(report.Results) == 0 && report.Inventory == nil && len(report.Progress) == 0 {
		return nil
	}
	response, err := r.Server.PostActions(ctx, report)
	if err != nil {
		r.mu.Lock()
		r.failures++
		r.retryAt = r.Now().Add(backoff(r.failures))
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.failures = 0
	r.retryAt = time.Time{}
	if response.InventoryHash != nil {
		r.acked = *response.InventoryHash
	}
	if listing != "" {
		r.sentList = listing
	}
	for _, step := range steps {
		r.steps[step.ID] = sentStep{step: step, at: r.Now()}
	}
	if refreshed && r.refreshAt.Equal(refreshAt) {
		r.refreshAt = time.Time{}
	}
	r.mu.Unlock()
	for _, result := range results {
		if err := os.Remove(filepath.Join(r.RequestDir, result.ID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (r *Relay) readProgress() []reporter.Progress {
	entries, _ := os.ReadDir(filepath.Join(r.StateDir, "progress"))
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.steps == nil {
		r.steps = map[string]sentStep{}
	}
	live := map[string]bool{}
	var steps []reporter.Progress
	for _, entry := range entries {
		if !requestName.MatchString(entry.Name()) {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		live[id] = true
		var step reporter.Progress
		if err := readJSON(filepath.Join(r.StateDir, "progress", entry.Name()), &step); err != nil || step.ID != id {
			continue
		}
		sent, before := r.steps[id]
		same := before && sent.step.Done == step.Done && sent.step.Total == step.Total && sent.step.Line == step.Line
		if !same && (!before || r.Now().Sub(sent.at) >= progressGap) && len(steps) < maxProgress {
			steps = append(steps, step)
		}
	}
	for id := range r.steps {
		if !live[id] {
			delete(r.steps, id)
		}
	}
	return steps
}

func (r *Relay) readResults() []Result {
	entries, err := os.ReadDir(r.RequestDir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, entry := range entries {
		if requestName.MatchString(entry.Name()) {
			ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	slices.Sort(ids)
	var results []Result
	total := 0
	for _, id := range ids {
		var result Result
		if err := readJSON(filepath.Join(r.StateDir, "results", id+".json"), &result); err != nil || result.ID != id {
			r.note(err)
			continue
		}
		result = fitted(result)
		total += len(result.Output)
		if len(results) > 0 && total > reportBudget {
			break
		}
		results = append(results, result)
		if len(results) == maxReported {
			break
		}
	}
	return results
}

func fitted(result Result) Result {
	units := 0
	for _, char := range result.Output {
		units++
		if char > 0xffff {
			units++
		}
	}
	if units <= maxResultText {
		return result
	}
	return Result{ID: result.ID, OK: false, Output: fmt.Sprintf("the result was %d KB, larger than the 64 KB a report can carry", len(result.Output)>>10), FinishedAt: result.FinishedAt}
}

func (r *Relay) Watch(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Poll(ctx); err != nil {
				log.Printf("report service actions: %v", err)
			}
		}
	}
}
