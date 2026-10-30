package cycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func targetURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func configWith(target, version string) reporter.AgentConfig {
	return reporter.AgentConfig{
		NodeID:          "node-1",
		IntervalSeconds: 60,
		ConfigVersion:   version,
		Checks: []reporter.Check{{
			ID: "http-1", Name: "Target", Kind: "HTTP",
			Target: target, TimeoutSeconds: 2,
		}},
	}
}

func TestFirstCycleFetchesConfigAndSendsResultsWithTheHeartbeat(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1"},
	}
	host := reporter.Host{
		Hostname: "test-host", OperatingSystem: "linux",
		Architecture: "amd64", AgentVersion: "test",
	}

	interval, err := New(server, host, nil, nil).Execute(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("execute cycle: %v", err)
	}
	if interval != 60 {
		t.Fatalf("expected interval 60, got %d", interval)
	}
	if server.fetches != 1 || server.heartbeats != 1 {
		t.Fatalf("expected 1 fetch and 1 heartbeat, got %d and %d", server.fetches, server.heartbeats)
	}
	if server.received.NodeID != "node-1" || server.received.Host != host {
		t.Fatalf("unexpected heartbeat: %#v", server.received)
	}
	if len(server.received.Results) != 1 || server.received.Results[0].Status != "UP" {
		t.Fatalf("expected one UP result, got %#v", server.received.Results)
	}
}

func TestSteadyCycleMakesOneRequest(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1"},
	}
	monitoring := New(server, reporter.Host{}, nil, nil)
	for index := 0; index < 3; index++ {
		if _, err := monitoring.Execute(context.Background(), "node-1"); err != nil {
			t.Fatalf("cycle %d: %v", index, err)
		}
	}
	if server.fetches != 1 || server.heartbeats != 3 {
		t.Fatalf("expected 1 fetch and 3 heartbeats, got %d and %d", server.fetches, server.heartbeats)
	}
}

func TestChangedConfigVersionRefetchesOnTheNextCycle(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v2"},
	}
	monitoring := New(server, reporter.Host{}, nil, nil)
	for index := 0; index < 2; index++ {
		if _, err := monitoring.Execute(context.Background(), "node-1"); err != nil {
			t.Fatalf("cycle %d: %v", index, err)
		}
	}
	if server.fetches != 2 {
		t.Fatalf("expected a refetch after the version changed, got %d fetches", server.fetches)
	}
}

func TestAChangedConfigAsksForOneImmediateRerun(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v2"},
	}
	monitoring := New(server, reporter.Host{}, nil, nil)
	if _, err := monitoring.Execute(context.Background(), "node-1"); err != nil {
		t.Fatal(err)
	}
	if !monitoring.ConfigChanged() {
		t.Fatal("a new config version should ask for a rerun")
	}
	if monitoring.ConfigChanged() {
		t.Fatal("the rerun is asked for once")
	}

	unversioned := &fakeReporter{
		config:    configWith(targetURL(t), ""),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60},
	}
	quiet := New(unversioned, reporter.Host{}, nil, nil)
	if _, err := quiet.Execute(context.Background(), "node-1"); err != nil {
		t.Fatal(err)
	}
	if quiet.ConfigChanged() {
		t.Fatal("a server without config versions must not cause reruns")
	}
}

func TestUnversionedServerRefetchesEveryCycle(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), ""),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60},
	}
	monitoring := New(server, reporter.Host{}, nil, nil)
	for index := 0; index < 2; index++ {
		if _, err := monitoring.Execute(context.Background(), "node-1"); err != nil {
			t.Fatalf("cycle %d: %v", index, err)
		}
	}
	if server.fetches != 2 {
		t.Fatalf("expected a fetch on every cycle without a config version, got %d fetches", server.fetches)
	}
}

func TestConfigFailureStillSendsTheHeartbeat(t *testing.T) {
	server := &fakeReporter{
		configError: &reporter.ResponseError{Status: 503, Body: "busy"},
		heartbeat:   reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60},
	}
	_, err := New(server, reporter.Host{}, nil, nil).Execute(context.Background(), "node-1")
	if err == nil || err.Error() != "fetch checks failed with HTTP 503: busy" {
		t.Fatalf("unexpected error: %v", err)
	}
	if server.heartbeats != 1 || len(server.received.Results) != 0 {
		t.Fatalf("expected a heartbeat without results, got %d heartbeats and %#v", server.heartbeats, server.received.Results)
	}
}

func TestHeartbeatFailureIsReported(t *testing.T) {
	server := &fakeReporter{
		config:         reporter.AgentConfig{NodeID: "node-1", ConfigVersion: "v1"},
		heartbeatError: &reporter.ResponseError{Status: 401, Body: "invalid agent"},
	}
	_, err := New(server, reporter.Host{}, nil, nil).Execute(context.Background(), "node-1")
	if err == nil || err.Error() != "heartbeat failed with HTTP 401: invalid agent" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFallsBackToTheConfiguredInterval(t *testing.T) {
	server := &fakeReporter{
		config:    reporter.AgentConfig{NodeID: "node-1", IntervalSeconds: 45, ConfigVersion: "v1"},
		heartbeat: reporter.HeartbeatResponse{OK: true, ConfigVersion: "v1"},
	}
	interval, err := New(server, reporter.Host{}, nil, nil).Execute(context.Background(), "node-1")
	if err != nil || interval != 45 {
		t.Fatalf("expected interval 45, got %d (%v)", interval, err)
	}
}

type fakeReporter struct {
	heartbeat      reporter.HeartbeatResponse
	heartbeatError error
	config         reporter.AgentConfig
	configError    error
	received       reporter.Heartbeat
	heartbeats     int
	fetches        int
}

func (server *fakeReporter) SendHeartbeat(
	_ context.Context,
	heartbeat reporter.Heartbeat,
) (reporter.HeartbeatResponse, error) {
	server.heartbeats++
	server.received = heartbeat
	return server.heartbeat, server.heartbeatError
}

func (server *fakeReporter) FetchConfig(context.Context) (reporter.AgentConfig, error) {
	server.fetches++
	return server.config, server.configError
}

var _ Reporter = (*fakeReporter)(nil)

type fakeUpdater struct {
	requests []string
	failure  *reporter.UpdateFailure
}

func (updater *fakeUpdater) Request(version, requestedAt string) error {
	updater.requests = append(updater.requests, version+"@"+requestedAt)
	return nil
}

func (updater *fakeUpdater) Failure() *reporter.UpdateFailure {
	return updater.failure
}

func TestTheLastUpdateFailureTravelsWithTheHeartbeat(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1"},
	}
	updates := &fakeUpdater{failure: &reporter.UpdateFailure{Version: "0.5.2", Message: "download stalled"}}
	if _, err := New(server, reporter.Host{}, updates, nil).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if server.received.Update == nil || server.received.Update.Message != "download stalled" {
		t.Fatalf("heartbeat update %+v", server.received.Update)
	}
}

func TestUpdateInstructionIsHandedToTheUpdater(t *testing.T) {
	server := &fakeReporter{
		config: configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{
			OK: true, IntervalSeconds: 60, ConfigVersion: "v1",
			Update: &reporter.UpdateInstruction{Version: "0.5.2", RequestedAt: "t1"},
		},
	}
	updates := &fakeUpdater{}
	if _, err := New(server, reporter.Host{}, updates, nil).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(updates.requests) != 1 || updates.requests[0] != "0.5.2@t1" {
		t.Fatalf("expected one update request, got %#v", updates.requests)
	}
}

func TestNoInstructionMeansNoUpdateRequest(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1"},
	}
	updates := &fakeUpdater{}
	if _, err := New(server, reporter.Host{}, updates, nil).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(updates.requests) != 0 {
		t.Fatalf("expected no update request, got %#v", updates.requests)
	}
}

type fakeActions struct {
	queued    []reporter.ActionRequest
	refreshes int
	beat      *reporter.NetworkBeat
	replies   []*reporter.NetworkReply
	events    []reporter.Event
	answers   []reporter.HeartbeatResponse
}

func (f *fakeActions) NetworkBeat() *reporter.NetworkBeat {
	return f.beat
}

func (f *fakeActions) NetworkReply(reply *reporter.NetworkReply) error {
	f.replies = append(f.replies, reply)
	return nil
}

func TestTheNetworkRidesTheHeartbeatAndItsReplyReachesTheRelay(t *testing.T) {
	reply := &reporter.NetworkReply{Endpoints: []reporter.NetworkEndpoint{{Key: "k", Endpoint: "203.0.113.21:51820"}}}
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1", Network: reply},
	}
	relay := &fakeActions{beat: &reporter.NetworkBeat{Version: 3}}
	if _, err := New(server, reporter.Host{}, nil, relay).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if server.received.Network == nil || server.received.Network.Version != 3 || len(relay.replies) != 1 || relay.replies[0] != reply {
		t.Fatalf("beat %#v replies %#v", server.received.Network, relay.replies)
	}
}

func (f *fakeActions) Report(beat *reporter.Heartbeat) {
	beat.Events = f.events
}

func (f *fakeActions) Answer(response reporter.HeartbeatResponse) error {
	f.answers = append(f.answers, response)
	return nil
}

func TestEventsRideTheHeartbeatAndTheAckReachesTheRelay(t *testing.T) {
	server := &fakeReporter{
		config:    configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{OK: true, IntervalSeconds: 60, ConfigVersion: "v1", Acked: []string{"port:aa"}, Quarantined: true},
	}
	relay := &fakeActions{events: []reporter.Event{{ID: "port:aa", Kind: "port", At: "2026-09-29T09:59:30Z"}}}
	if _, err := New(server, reporter.Host{}, nil, relay).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(server.received.Events) != 1 || len(relay.answers) != 1 || relay.answers[0].Acked[0] != "port:aa" || !relay.answers[0].Quarantined {
		t.Fatalf("beat %#v answers %#v", server.received.Events, relay.answers)
	}
}

func (f *fakeActions) Enqueue(requests []reporter.ActionRequest) error {
	f.queued = append(f.queued, requests...)
	return nil
}

func (f *fakeActions) Refresh() error {
	f.refreshes++
	return nil
}

func TestActionsAndRefreshesAreHandedToTheRelay(t *testing.T) {
	server := &fakeReporter{
		config: configWith(targetURL(t), "v1"),
		heartbeat: reporter.HeartbeatResponse{
			OK: true, IntervalSeconds: 60, ConfigVersion: "v1", Refresh: true,
			Actions: []reporter.ActionRequest{{ID: "a", Kind: "docker", Name: "resolver", Action: "restart"}},
		},
	}
	relay := &fakeActions{}
	if _, err := New(server, reporter.Host{}, nil, relay).Execute(context.Background(), "node-1"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(relay.queued) != 1 || relay.refreshes != 1 {
		t.Fatalf("queued %#v refreshes %d", relay.queued, relay.refreshes)
	}
}
