package service

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/stream"
	"github.com/Kleavox/krynodes/agent/internal/trust"
	"github.com/Kleavox/krynodes/agent/windows/internal/exit"
	"github.com/Kleavox/krynodes/agent/windows/internal/meet"
)

const (
	wireguardSecret = "wireguard"
	signerSecret    = "signer"
	sealSecret      = "seal"
	tokenSecret     = "token"
	stateFile       = "state.json"
	trustFile       = "trust.json"
	expirySkew      = time.Minute
	maxResults      = 10
	ledgerKept      = 30 * 24 * time.Hour
)

type Secrets interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Write(path string, data []byte) error
}

type server interface {
	SendHeartbeat(context.Context, reporter.Heartbeat) (reporter.HeartbeatResponse, error)
	PostActions(context.Context, reporter.ActionsReport) (reporter.ActionsResponse, error)
}

type state struct {
	Endpoint  string                    `json:"endpoint"`
	NodeID    string                    `json:"nodeId"`
	Interval  int                       `json:"interval"`
	Applied   network.Applied           `json:"applied"`
	Joined    bool                      `json:"joined,omitempty"`
	Document  *network.Document         `json:"document,omitempty"`
	Announce  *reporter.NetworkAnnounce `json:"announce,omitempty"`
	Announced map[string]string         `json:"announced,omitempty"`
	Endpoints map[string]string         `json:"endpoints,omitempty"`
	Removed   bool                      `json:"removed,omitempty"`
	Offline   bool                      `json:"notifyOffline,omitempty"`
	Ledger    map[string]time.Time      `json:"ledger,omitempty"`
	Results   []reporter.ActionResult   `json:"results,omitempty"`
}

type Service struct {
	Dir     string
	Secrets Secrets
	Now     func() time.Time
	Apply   func(Wanted)
	Ping    func(address string) (time.Duration, bool)

	mu        sync.Mutex
	applying  sync.Mutex
	pending   *Wanted
	off       bool
	linked    bool
	notes     []note
	noteID    uint64
	health    map[string]*health
	meet      string
	exit      string
	local     bool
	held      []string
	connected []string
	chooser   meet.Chooser
	watch     exit.ExitWatch
	watching  string
	wake      chan struct{}
	last      Wanted
	queued    []reporter.ActionRequest
	acked     string
	interval  time.Duration
}

func laptopWords(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "this server's", "this laptop's"), "this server", "this laptop")
}

func (s *Service) read() (state, error) {
	var current state
	raw, err := safefile.Read(filepath.Join(s.Dir, stateFile), 1<<20)
	if err != nil {
		return current, err
	}
	return current, json.Unmarshal(raw, &current)
}

func (s *Service) save(current state) error {
	return s.keep(stateFile, current)
}

func (s *Service) keep(name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Secrets.Write(filepath.Join(s.Dir, name), encoded)
}

func newKeys(secrets Secrets) (network.Keys, *ecdh.PrivateKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, nil, err
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, nil, err
	}
	sealing, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, nil, err
	}
	for _, secret := range []struct {
		name  string
		value []byte
	}{{wireguardSecret, private.Bytes()}, {signerSecret, signer.Seed()}, {sealSecret, sealing.Bytes()}} {
		if err := secrets.Put(secret.name, secret.value); err != nil {
			return network.Keys{}, nil, err
		}
	}
	keys, err := network.KeysOf(private.Bytes(), signer.Seed())
	return keys, sealing, err
}

func (s *Service) keys() (network.Keys, error) {
	private, err := s.Secrets.Get(wireguardSecret)
	if err != nil {
		return network.Keys{}, err
	}
	seed, err := s.Secrets.Get(signerSecret)
	if err != nil {
		return network.Keys{}, err
	}
	return network.KeysOf(private, seed)
}

func (s *Service) newKey() (network.Keys, []byte, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, nil, err
	}
	seed, err := s.Secrets.Get(signerSecret)
	if err != nil {
		return network.Keys{}, nil, err
	}
	keys, err := network.KeysOf(private.Bytes(), seed)
	return keys, private.Bytes(), err
}

func (s *Service) presharedKeys(self network.Member, document network.Document) (map[string]string, error) {
	raw, err := s.Secrets.Get(sealSecret)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	keys := map[string]string{}
	for node, sealed := range self.PSK {
		plain, err := seal.Open(key, sealed)
		if err != nil || len(plain) != 32 {
			peer, _ := member(document, node)
			return nil, fmt.Errorf("the preshared key for %s cannot be opened on this laptop", peer.Name)
		}
		keys[node] = base64.StdEncoding.EncodeToString(plain)
	}
	return keys, nil
}

func current(document network.Document, announced, endpoints map[string]string) network.Document {
	document.Members = slices.Clone(document.Members)
	for index, entry := range document.Members {
		if key, ok := announced[entry.Node]; ok {
			document.Members[index].Key = key
		}
		if endpoint, ok := endpoints[document.Members[index].Key]; ok && !entry.NAT {
			document.Members[index].Endpoint = &endpoint
		}
	}
	return document
}

func (s *Service) applyDocument(signed json.RawMessage) error {
	trusted, err := trust.Load(s.Dir)
	if err != nil {
		return err
	}
	body, err := trust.VerifyDocument(trusted, signed, s.Now())
	if err != nil {
		return err
	}
	document, err := network.Parse(body)
	if err != nil {
		return err
	}
	record, err := s.read()
	if err != nil {
		return err
	}
	hash := network.BodyHash(body)
	self, err := network.Accept(document, record.Applied, trusted.NodeID, record.Joined)
	if errors.Is(err, network.ErrLeave) {
		record.Applied, record.Joined, record.Document = record.Applied.After(document, hash), false, nil
		record.Announce, record.Announced, record.Endpoints = nil, nil, nil
		return s.save(record)
	}
	if err != nil {
		return err
	}
	keys, err := s.keys()
	if err != nil {
		return errors.New("this laptop has no network key; add it again")
	}
	rekey := self.Key == keys.Public && self.Rekey
	if self.Key != keys.Public && (record.Announce == nil || record.Announce.Key != keys.Public) {
		return fmt.Errorf("the document names another key for %s", self.Name)
	}
	if _, err := s.presharedKeys(self, document); err != nil {
		return err
	}
	if self.Key == keys.Public && !rekey {
		record.Announce = nil
	}
	if rekey {
		next, private, err := s.newKey()
		if err != nil {
			return err
		}
		record.Announce = &reporter.NetworkAnnounce{Key: next.Public, Signature: next.Announce(trusted.NodeID)}
		if err := s.save(record); err != nil {
			return err
		}
		if err := s.Secrets.Put(wireguardSecret, private); err != nil {
			return err
		}
	}
	for node, key := range record.Announced {
		if entry, ok := member(document, node); !ok || entry.Key == key || slices.Contains(document.Blocked, key) {
			delete(record.Announced, node)
		}
	}
	record.Applied, record.Joined, record.Document, record.Endpoints = record.Applied.After(document, hash), true, &document, nil
	return s.save(record)
}

func newer(signed json.RawMessage, applied int) bool {
	var envelope trust.SignedDocument
	var head struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(signed, &envelope) != nil {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(envelope.Document)
	return err == nil && json.Unmarshal(body, &head) == nil && head.Version > applied
}

func (s *Service) takeHints(reply *reporter.NetworkReply) error {
	record, err := s.read()
	if err != nil || !record.Joined || record.Document == nil {
		return err
	}
	changed := false
	for _, announced := range reply.Announced {
		peer, ok := member(*record.Document, announced.Node)
		if !ok || announced.Node == record.NodeID || record.Announced[announced.Node] == announced.Key || slices.Contains(record.Applied.Blocked, announced.Key) {
			continue
		}
		if !network.Announced(peer.Signer, announced.Node, announced.Key, announced.Signature) {
			log.Printf("ignoring a new key for %s: not signed by it", peer.Name)
			continue
		}
		if record.Announced == nil {
			record.Announced = map[string]string{}
		}
		record.Announced[announced.Node], changed = announced.Key, true
	}
	listening := map[string]bool{}
	for _, entry := range current(*record.Document, record.Announced, nil).Members {
		listening[entry.Key] = !entry.NAT && entry.Node != record.NodeID
	}
	for _, entry := range reply.Endpoints {
		parsed, err := netip.ParseAddrPort(entry.Endpoint)
		if err != nil || !listening[entry.Key] || parsed.Port() < network.FirstPort || parsed.Port() > network.LastPort || record.Endpoints[entry.Key] == parsed.String() {
			continue
		}
		if record.Endpoints == nil {
			record.Endpoints = map[string]string{}
		}
		record.Endpoints[entry.Key], changed = parsed.String(), true
	}
	if !changed {
		return nil
	}
	return s.save(record)
}

func (s *Service) wanted() Wanted {
	record, err := s.read()
	if err != nil || record.Removed || s.off || !record.Joined || record.Document == nil {
		return Wanted{}
	}
	document := current(*record.Document, record.Announced, record.Endpoints)
	self, ok := member(document, record.NodeID)
	if !ok {
		return Wanted{}
	}
	psk, err := s.presharedKeys(self, document)
	if err != nil {
		log.Printf("the tunnel stays down: %v", err)
		return Wanted{}
	}
	private, err := s.Secrets.Get(wireguardSecret)
	if err != nil {
		log.Printf("the tunnel stays down: %v", err)
		return Wanted{}
	}
	chosen := ""
	if entry, ok := member(document, s.exit); ok && exit.Offered(*record.Document, s.held, s.exit) {
		chosen = entry.Node
		if len(document.DNS) == 0 {
			log.Printf("the private network has no DNS for laptops, so the exit node through %s is off", entry.Name)
			s.exit, chosen = "", ""
		}
	}
	peers := laptopPeers(document, *record.Document, self, meetingOf(*record.Document, s.meet, s.held), chosen, psk)
	mtu := document.MTU
	if self.MTU != nil {
		mtu = *self.MTU
	}
	return Wanted{
		Peers:   peers,
		Address: self.Address,
		DNS:     slices.Clone(document.DNS),
		Exit:    chosen,
		Held:    slices.Clone(s.held),
		Key:     private,
		MTU:     mtu,
		Local:   s.local,
	}
}

type answer struct {
	rtt time.Duration
	ok  bool
}

func (s *Service) targets() map[string]string {
	if len(s.last.Peers) == 0 {
		return nil
	}
	record, err := s.read()
	if err != nil || record.Document == nil {
		return nil
	}
	servers := map[string]string{}
	for _, entry := range reached(*record.Document, record.NodeID) {
		servers[entry.Node] = entry.Address
	}
	return servers
}

func reached(document network.Document, self string) []network.Member {
	var servers []network.Member
	for _, entry := range document.Members {
		if entry.Node != self && !entry.IsLaptop() && !entry.Cut {
			servers = append(servers, entry)
		}
	}
	return servers
}

func (s *Service) observe(now time.Time, answers map[string]answer) {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil || record.Document == nil {
		return
	}
	var allowed []string
	for node := range answers {
		if entry, ok := member(*record.Document, node); ok && network.MeetingPoint(entry) && !slices.Contains(s.held, node) {
			allowed = append(allowed, node)
		}
	}
	s.chooser.Only(allowed)
	for node, got := range answers {
		s.chooser.Observe(now, node, got.rtt, got.ok)
	}
	if answered, counted := s.through(*record.Document, record.NodeID, answers); s.linked {
		s.chooser.Through(now, meetingOf(*record.Document, s.meet, s.held), answered || !counted)
	}
	s.listen(now, record, answers)
	changed := false
	if point := s.chooser.Current(s.linked); point != s.meet {
		s.meet, changed = point, true
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	if s.exit != "" && len(s.last.Peers) > 0 && s.watchExit(now, answers[s.exit].ok) {
		changed = true
	}
	if changed {
		s.refresh()
	}
}

func (s *Service) through(signed network.Document, self string, answers map[string]answer) (bool, bool) {
	laptop, ok := member(signed, self)
	if !ok {
		return false, false
	}
	answered, counted := false, false
	for _, node := range s.connected {
		got, pinged := answers[node]
		if _, relayed := laptop.Relay[node]; !pinged || !relayed {
			continue
		}
		if entry, ok := member(signed, node); !ok || entry.Cut || !entry.NAT {
			continue
		}
		answered, counted = answered || got.ok, true
	}
	return answered, counted
}

func (s *Service) watchExit(now time.Time, answered bool) bool {
	record, err := s.read()
	if err != nil || record.Document == nil {
		return false
	}
	if s.watching != s.exit {
		s.watch, s.watching = exit.ExitWatch{}, s.exit
	}
	server, ok := member(*record.Document, s.exit)
	if ok && server.Exit {
		held := server.Cut || slices.Contains(s.held, server.Node)
		if s.watch.Observe(now, answered, held) {
			return false
		}
		line := server.Name + " stopped answering, so the exit node is off."
		if held {
			line = server.Name + " was cut off, so the exit node is off."
		}
		s.say(line)
	}
	s.exit, s.watching = "", ""
	return true
}

func (s *Service) pings(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		servers := s.targets()
		s.mu.Unlock()
		answers := make(map[string]answer, len(servers))
		var lock sync.Mutex
		var wait sync.WaitGroup
		for node, address := range servers {
			wait.Go(func() {
				rtt, ok := s.Ping(address)
				lock.Lock()
				answers[node] = answer{rtt: rtt, ok: ok}
				lock.Unlock()
			})
		}
		wait.Wait()
		if len(answers) > 0 {
			s.observe(s.Now(), answers)
		}
	}
}

func (s *Service) refresh() {
	next := s.wanted()
	if reflect.DeepEqual(next, s.last) {
		return
	}
	s.last, s.pending = next, &next
}

func (s *Service) push() {
	s.applying.Lock()
	defer s.applying.Unlock()
	s.mu.Lock()
	next := s.pending
	s.pending = nil
	s.mu.Unlock()
	if next != nil && s.Apply != nil {
		s.Apply(*next)
	}
}

func (s *Service) gone(gone bool) {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil || record.Removed == gone {
		return
	}
	record.Removed = gone
	if err := s.save(record); err != nil {
		log.Printf("record that this laptop was removed: %v", err)
	}
	if gone {
		log.Printf("Krynodes no longer knows this laptop; the tunnel is down and the keys are kept")
	}
	s.refresh()
}

func (s *Service) Removed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	return err == nil && record.Removed
}

func (s *Service) deliver(requests []reporter.ActionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue(requests)
	return nil
}

func (s *Service) queue(requests []reporter.ActionRequest) {
	record, _ := s.read()
	for _, request := range requests {
		_, done := record.Ledger[request.ID]
		if !done && !slices.ContainsFunc(s.queued, func(queued reporter.ActionRequest) bool { return queued.ID == request.ID }) {
			s.queued = append(s.queued, request)
		}
	}
}

func (s *Service) act(request reporter.ActionRequest) reporter.ActionResult {
	now := s.Now()
	result := reporter.ActionResult{ID: request.ID, FinishedAt: now.UTC().Format(time.RFC3339Nano)}
	refuse := func(err error) reporter.ActionResult {
		result.Output = "refused: " + laptopWords(err.Error())
		return result
	}
	if request.Kind != "trust" || request.Name != "devices" || request.Action != "trust" {
		return refuse(errors.New("unknown action"))
	}
	expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		return refuse(errors.New("invalid expiry"))
	}
	if now.After(expires.Add(expirySkew)) {
		return refuse(fmt.Errorf("the request expired at %s", trust.ClockSays(expires, now)))
	}
	trusted, err := trust.Load(s.Dir)
	if err != nil {
		return refuse(err)
	}
	next, err := trust.ApplyTrustChange(trusted, request, now)
	if err != nil {
		return refuse(err)
	}
	if err := s.keep(trustFile, next); err != nil {
		return refuse(err)
	}
	result.OK = true
	result.Output = fmt.Sprintf("%d trusted devices, version %d", len(next.Core), next.Version)
	return result
}

func (s *Service) answer(response reporter.HeartbeatResponse) {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linked = true
	if response.IntervalSeconds >= 15 && response.IntervalSeconds <= 3600 {
		s.interval = time.Duration(response.IntervalSeconds) * time.Second
	}
	if response.Refresh {
		s.acked = ""
	}
	s.queue(response.Actions)
	if reply := response.Network; reply != nil {
		if reply.Held != nil {
			s.held = reply.Held
		}
		if reply.Connected != nil {
			s.connected = reply.Connected
		}
		if record, err := s.read(); err == nil && len(reply.Document) > 0 && newer(reply.Document, record.Applied.Version) {
			if err := s.applyDocument(reply.Document); err != nil {
				log.Printf("network document refused: %s", laptopWords(err.Error()))
			}
		}
		if err := s.takeHints(reply); err != nil {
			log.Printf("network hints: %v", err)
		}
	}
	s.refresh()
}

func (s *Service) beat(host reporter.Host) (reporter.Heartbeat, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil {
		log.Printf("read the laptop's state: %v", err)
		return reporter.Heartbeat{}, false
	}
	beat := reporter.Heartbeat{NodeID: record.NodeID, Host: host}
	if keys, err := s.keys(); err == nil {
		public := keys.Public
		beat.Network = &reporter.NetworkBeat{Version: record.Applied.Version, Key: &public, Links: []network.Link{}, Announce: record.Announce, Meet: s.meet}
	}
	return beat, true
}

func (s *Service) report(node string) (reporter.ActionsReport, bool) {
	queued := s.queued
	s.queued = nil
	record, err := s.read()
	if err != nil {
		log.Printf("read the laptop's state: %v", err)
		return reporter.ActionsReport{}, false
	}
	now := s.Now()
	for id, at := range record.Ledger {
		if now.Sub(at) > ledgerKept {
			delete(record.Ledger, id)
		}
	}
	for _, request := range queued {
		if record.Ledger == nil {
			record.Ledger = map[string]time.Time{}
		}
		record.Ledger[request.ID] = now
		if err := s.save(record); err != nil {
			log.Printf("record action %s: %v", request.ID, err)
			continue
		}
		record.Results = append(record.Results, s.act(request))
		if err := s.save(record); err != nil {
			log.Printf("record the result of action %s: %v", request.ID, err)
		}
	}
	report := reporter.ActionsReport{NodeID: node, Results: slices.Clone(record.Results[:min(len(record.Results), maxResults)])}
	if trusted, err := trust.Load(s.Dir); err == nil {
		devices := trusted.Report()
		encoded, err := json.Marshal(devices)
		sum := sha256.Sum256(encoded)
		if hash := hex.EncodeToString(sum[:]); err == nil && hash != s.acked {
			report.Inventory = &reporter.InventoryReport{Hash: hash, Trust: &devices}
		}
	}
	return report, len(report.Results) > 0 || report.Inventory != nil
}

func (s *Service) cycle(ctx context.Context, to server, host reporter.Host) {
	beat, ok := s.beat(host)
	if !ok {
		return
	}
	response, err := to.SendHeartbeat(ctx, beat)
	if err != nil {
		s.mu.Lock()
		s.linked = false
		s.mu.Unlock()
		if !errors.Is(err, stream.ErrNotConnected) {
			log.Printf("heartbeat: %v", err)
		}
		return
	}
	s.answer(response)
	s.mu.Lock()
	report, sending := s.report(beat.NodeID)
	s.mu.Unlock()
	if !sending {
		return
	}
	answered, err := to.PostActions(ctx, report)
	if err != nil {
		log.Printf("report: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if answered.InventoryHash != nil {
		s.acked = *answered.InventoryHash
	}
	if len(report.Results) == 0 {
		return
	}
	record, err := s.read()
	if err != nil {
		log.Printf("read the laptop's state: %v", err)
		return
	}
	record.Results = slices.DeleteFunc(record.Results, func(result reporter.ActionResult) bool {
		return slices.ContainsFunc(report.Results, func(sent reporter.ActionResult) bool { return sent.ID == result.ID })
	})
	if err := s.save(record); err != nil {
		log.Printf("forget the posted results: %v", err)
	}
}

func (s *Service) Run(ctx context.Context, version string) error {
	record, err := s.read()
	if err != nil {
		return fmt.Errorf("this laptop is not added (%v); run install again", err)
	}
	token, err := s.Secrets.Get(tokenSecret)
	if err != nil {
		return fmt.Errorf("the agent token cannot be read (%v); run install again", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	host := reporter.Host{Hostname: hostname, OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, AgentVersion: version}
	s.mu.Lock()
	s.interval = time.Duration(record.Interval) * time.Second
	s.wake = make(chan struct{}, 1)
	s.refresh()
	s.mu.Unlock()
	s.push()
	if s.Ping != nil {
		go s.pings(ctx)
	}
	client := stream.New(record.Endpoint, string(token), version)
	client.Deliver = s.deliver
	client.Gone = s.gone
	client.Noun = "laptop"
	client.Unknown = "Krynodes does not know this laptop any more (it was removed or its token replaced); the tunnel stays down until it is added again"
	go client.Run(ctx)
	for {
		s.cycle(ctx, client, host)
		s.mu.Lock()
		wait := s.interval
		s.mu.Unlock()
		timer := time.NewTimer(max(wait, 15*time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case <-client.Pokes():
			timer.Stop()
		case <-client.Ready():
			timer.Stop()
		case <-s.wake:
			timer.Stop()
		}
	}
}
