package service

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
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
	maxMessage      = 2048
)

type Secrets interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Write(path string, data []byte) error
}

type hub interface {
	Send(message any) error
	HelloAgain() error
}

type state struct {
	Endpoint  string             `json:"endpoint"`
	NodeID    string             `json:"nodeId"`
	Applied   network.Applied    `json:"applied"`
	Joined    bool               `json:"joined,omitempty"`
	Document  *network.Document  `json:"document,omitempty"`
	Announce  *reporter.Announce `json:"announce,omitempty"`
	Announced map[string]string  `json:"announced,omitempty"`
	Endpoints map[string]string  `json:"endpoints,omitempty"`
	Offline   bool               `json:"notifyOffline,omitempty"`
	Offered   string             `json:"offered,omitempty"`
}

type Service struct {
	Dir     string
	Secrets Secrets
	Now     func() time.Time
	Apply   func(Wanted) error
	Ping    func(address string) (time.Duration, bool)
	Kernel  string

	hub       hub
	mu        sync.Mutex
	applying  sync.Mutex
	pending   *Wanted
	why       string
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
	last      Wanted
}

var laptopWords = strings.NewReplacer("this server's", "this laptop's", "this server", "this laptop", "This server", "This laptop").Replace

func clip(text string, most int) string {
	if len(text) <= most {
		return text
	}
	cut := most
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
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
	sealing, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, nil, err
	}
	if err := secrets.Put(sealSecret, sealing.Bytes()); err != nil {
		return network.Keys{}, nil, err
	}
	keys, err := networkKeys(secrets)
	return keys, sealing, err
}

func networkKeys(secrets Secrets) (network.Keys, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, err
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return network.Keys{}, err
	}
	if err := secrets.Put(signerSecret, signer.Seed()); err != nil {
		return network.Keys{}, err
	}
	if err := secrets.Put(wireguardSecret, private.Bytes()); err != nil {
		return network.Keys{}, err
	}
	return network.KeysOf(private.Bytes(), signer.Seed())
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

func (s *Service) sealing() (*ecdh.PrivateKey, error) {
	raw, err := s.Secrets.Get(sealSecret)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPrivateKey(raw)
}

func (s *Service) fingerprint() string {
	keys, err := s.keys()
	if err != nil {
		return ""
	}
	sealing, err := s.sealing()
	if err != nil {
		return ""
	}
	return network.Fingerprint(keys.Public, keys.Signer, seal.Public(sealing))
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
	key, err := s.sealing()
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

func (s *Service) receive(message any) {
	switch value := message.(type) {
	case reporter.Document:
		s.document(value.Version, value.Signed)
	case reporter.Hints:
		s.hints(value)
	}
}

func (s *Service) send(message any) {
	if s.hub == nil {
		return
	}
	if err := s.hub.Send(message); err != nil && !errors.Is(err, stream.ErrNotConnected) {
		log.Printf("tell Krynodes: %v", err)
	}
}

func (s *Service) document(version int, signed string) {
	s.mu.Lock()
	message, at, announce, left, err := s.apply(version, []byte(signed))
	s.refresh()
	s.mu.Unlock()
	s.push()
	answer := reporter.Applied{Type: "applied", Version: at, OK: err == nil, Message: message}
	if err != nil {
		answer.Message = laptopWords(err.Error())
		log.Printf("network document %d refused: %s", version, answer.Message)
	}
	answer.Message = clip(answer.Message, maxMessage)
	s.send(answer)
	if announce != nil {
		s.send(*announce)
	}
	if left && s.hub != nil {
		if err := s.hub.HelloAgain(); err != nil && !errors.Is(err, stream.ErrNotConnected) {
			log.Printf("tell Krynodes the new network keys: %v", err)
		}
	}
}

func (s *Service) apply(version int, signed []byte) (string, int, *reporter.Announce, bool, error) {
	record, err := s.read()
	if err != nil {
		return "", version, nil, false, err
	}
	if version <= record.Applied.Version {
		return "Already applied.", record.Applied.Version, nil, false, nil
	}
	trusted, err := trust.Load(s.Dir)
	if err != nil {
		return "", version, nil, false, err
	}
	body, err := trust.VerifyDocument(trusted, signed, s.Now())
	if err != nil {
		return "", version, nil, false, err
	}
	document, err := network.Parse(body)
	if err != nil {
		return "", version, nil, false, err
	}
	if document.Version != version {
		return "", version, nil, false, fmt.Errorf("the signed document is version %d, not %d", document.Version, version)
	}
	hash := network.BodyHash(body)
	self, err := network.Accept(document, record.Applied, trusted.NodeID, record.Joined)
	if errors.Is(err, network.ErrLeave) {
		message, left, err := s.leave(record, record.Applied.After(document, hash))
		return message, version, nil, left, err
	}
	if err != nil {
		return "", version, nil, false, err
	}
	keys, err := s.keys()
	if err != nil {
		return "", version, nil, false, errors.New("this laptop has no network keys")
	}
	own := ""
	if record.Document != nil {
		if entry, ok := member(*record.Document, trusted.NodeID); ok {
			own = entry.Key
		}
	}
	pending := record.Announce != nil && record.Announce.Key == keys.Public
	if self.Signer != keys.Signer || (self.Key != keys.Public && (!pending || self.Key != own)) {
		return "", version, nil, false, fmt.Errorf("the document names another key for %s", self.Name)
	}
	if sealing, err := s.sealing(); err != nil || self.SealKey != seal.Public(sealing) {
		return "", version, nil, false, fmt.Errorf("the document names another seal key for %s", self.Name)
	}
	if _, err := s.presharedKeys(self, document); err != nil {
		return "", version, nil, false, err
	}
	if self.Key == keys.Public {
		record.Announce = nil
	}
	if self.Key == keys.Public && self.Rekey {
		next, private, err := s.newKey()
		if err != nil {
			return "", version, nil, false, err
		}
		record.Announce = &reporter.Announce{Type: "announce", Key: next.Public, Signature: next.Announce(trusted.NodeID)}
		if err := s.save(record); err != nil {
			return "", version, nil, false, err
		}
		if err := s.Secrets.Put(wireguardSecret, private); err != nil {
			return "", version, nil, false, err
		}
	}
	for node, key := range record.Announced {
		if entry, ok := member(document, node); !ok || entry.Cut || entry.Key == key || slices.Contains(document.Blocked, key) {
			delete(record.Announced, node)
		}
	}
	if !record.Joined {
		s.off = false
	}
	record.Applied, record.Joined, record.Document, record.Endpoints = record.Applied.After(document, hash), true, &document, nil
	if err := s.save(record); err != nil {
		return "", version, nil, false, err
	}
	return fmt.Sprintf("Applied version %d.", version), version, record.Announce, false, nil
}

func (s *Service) leave(record state, applied network.Applied) (string, bool, error) {
	joined := record.Joined
	record = state{Endpoint: record.Endpoint, NodeID: record.NodeID, Applied: applied, Offline: record.Offline, Offered: record.Offered}
	if !joined {
		return "This laptop is not in the private network.", false, s.save(record)
	}
	s.exit, s.watching, s.health = "", "", nil
	var problems []string
	if _, err := networkKeys(s.Secrets); err != nil {
		problems = append(problems, "make new network keys: "+err.Error())
	}
	left := false
	if err := s.save(record); err != nil {
		problems = append(problems, err.Error())
	} else {
		left = true
	}
	if len(problems) > 0 {
		return "", left, fmt.Errorf("left the private network, but: %s", strings.Join(problems, "; "))
	}
	return "Left the private network.", true, nil
}

func (s *Service) hints(hints reporter.Hints) {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linked = true
	s.held, s.connected = hints.Held, hints.Connected
	if err := s.takeHints(hints); err != nil {
		log.Printf("network hints: %v", err)
	}
	s.refresh()
}

func (s *Service) takeHints(hints reporter.Hints) error {
	record, err := s.read()
	if err != nil || !record.Joined || record.Document == nil {
		return err
	}
	changed := false
	for _, announced := range hints.Announced {
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
	for _, entry := range hints.Endpoints {
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

func (s *Service) wanted() (Wanted, string) {
	const outside = "this laptop is not in the private network"
	record, err := s.read()
	switch {
	case err != nil:
		return Wanted{}, err.Error()
	case s.off:
		return Wanted{}, "disconnected in the tray"
	case !record.Joined || record.Document == nil:
		return Wanted{}, outside
	}
	document := current(*record.Document, record.Announced, record.Endpoints)
	self, ok := member(document, record.NodeID)
	if !ok {
		return Wanted{}, outside
	}
	psk, err := s.presharedKeys(self, document)
	if err != nil {
		log.Printf("the tunnel stays down: %v", err)
		return Wanted{}, err.Error()
	}
	private, err := s.Secrets.Get(wireguardSecret)
	if err != nil {
		log.Printf("the tunnel stays down: %v", err)
		return Wanted{}, err.Error()
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
		Held:    append([]string(nil), s.held...),
		Key:     private,
		MTU:     mtu,
		Local:   s.local,
	}, fmt.Sprintf("v%d, %d peers", record.Document.Version, len(peers))
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
	if via := s.watchPings(now, answers); via != "" {
		s.send(reporter.Meet{Type: "meet", Via: via})
	}
	s.push()
}

func (s *Service) watchPings(now time.Time, answers map[string]answer) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil || record.Document == nil {
		return ""
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
	moved, changed := "", false
	if point := s.chooser.Current(s.linked); point != s.meet {
		s.meet, moved, changed = point, point, true
	}
	if s.exit != "" && len(s.last.Peers) > 0 && s.watchExit(now, answers[s.exit].ok) {
		changed = true
	}
	if changed {
		s.refresh()
	}
	return moved
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
	next, why := s.wanted()
	if reflect.DeepEqual(next, s.last) {
		return
	}
	s.last, s.pending, s.why = next, &next, why
}

func (s *Service) push() {
	s.applying.Lock()
	defer s.applying.Unlock()
	s.mu.Lock()
	next, why := s.pending, s.why
	s.pending = nil
	s.mu.Unlock()
	if next == nil || s.Apply == nil {
		return
	}
	switch err := s.Apply(*next); {
	case err != nil:
		log.Printf("tunnel: %v", err)
	case next.Address != "":
		log.Printf("tunnel up (%s)", why)
	default:
		log.Printf("tunnel down (%s)", why)
	}
}

func (s *Service) setLinked(linked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linked = linked
}

func (s *Service) reconnected() {
	s.mu.Lock()
	s.linked = true
	via := s.meet
	record, err := s.read()
	s.mu.Unlock()
	if err == nil && record.Announce != nil {
		s.send(*record.Announce)
	}
	if via != "" {
		s.send(reporter.Meet{Type: "meet", Via: via})
	}
}

func known(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func (s *Service) hello(version string) reporter.Hello {
	hostname, _ := os.Hostname()
	message := reporter.Hello{Type: "hello", V: 1, Version: version, Hostname: known(hostname), OS: runtime.GOOS, Arch: runtime.GOARCH, Kernel: known(s.Kernel), Kind: "laptop"}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sealing, err := s.sealing(); err == nil {
		message.SealKey = seal.Public(sealing)
	}
	if trusted, err := trust.Load(s.Dir); err == nil && len(trusted.Core) > 0 {
		report := trusted.Report()
		message.Trust = &report
	}
	record, err := s.read()
	keys, missing := s.keys()
	if err == nil && missing == nil {
		message.Network = &reporter.NetworkHello{Version: record.Applied.Version, Key: keys.Public, Signer: keys.Signer, Ready: true}
	}
	return message
}

func (s *Service) daemon() *daemon.Daemon {
	d := &daemon.Daemon{
		State: s.Dir,
		Trust: func() trust.Trust {
			current, err := trust.Load(s.Dir)
			if err != nil {
				log.Print(err)
			}
			return current
		},
		SaveTrust: func(next trust.Trust) error { return s.keep(trustFile, next) },
		Send: func(message any) error {
			if result, ok := message.(reporter.Result); ok {
				result.Message = laptopWords(result.Message)
				message = result
			}
			if s.hub == nil {
				return stream.ErrNotConnected
			}
			return s.hub.Send(message)
		},
		Now: s.Now,
	}
	d.Handlers = map[string]daemon.Handler{"trust/apply": d.ApplyTrust}
	return d
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
	client := stream.New(record.Endpoint, string(token), version)
	s.hub = client
	d := s.daemon()
	client.Hello = func() any { return s.hello(version) }
	client.Connected = func() {
		d.Resend()
		s.reconnected()
	}
	client.Disconnected = func() { s.setLinked(false) }
	client.Command = func(command reporter.Command) { go d.Handle(ctx, command) }
	client.Ack = d.Ack
	client.Network = s.receive
	s.mu.Lock()
	s.refresh()
	s.mu.Unlock()
	s.push()
	if s.Ping != nil {
		go s.pings(ctx)
	}
	go d.Start(ctx)
	client.Run(ctx)
	return nil
}
