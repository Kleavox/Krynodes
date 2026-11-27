package service

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func (f *fixture) edited(body []byte, edit func(*network.Document)) []byte {
	f.t.Helper()
	var document network.Document
	if err := json.Unmarshal(body, &document); err != nil {
		f.t.Fatal(err)
	}
	edit(&document)
	edited, err := json.Marshal(document)
	if err != nil {
		f.t.Fatal(err)
	}
	return edited
}

func TestALaptopAppliesTheNextDocumentOnly(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	if got := f.deliver(1, f.sign(first)); got != (reporter.Applied{Type: "applied", Version: 1, OK: true, Message: "Applied version 1."}) {
		t.Fatalf("first %+v", got)
	}
	if up := f.last(); len(up.Peers) != 2 || up.Address != "10.88.0.10" {
		t.Fatalf("tunnel %+v", up)
	}
	second := f.document(2, network.BodyHash(first), true)
	third := f.document(3, network.BodyHash(second), true)
	if got := f.deliver(3, f.sign(third)); got.OK || got.Version != 3 || got.Message != "version 3 is not the next one after 1" {
		t.Fatalf("a skipped version %+v", got)
	}
	if got := f.deliver(1, f.sign(first)); got != (reporter.Applied{Type: "applied", Version: 1, OK: true, Message: "Already applied."}) {
		t.Fatalf("again %+v", got)
	}
	stray := f.document(2, network.BodyHash([]byte("another chain")), true)
	if got := f.deliver(2, f.sign(stray)); got.OK || got.Message != "version 2 does not follow the version this laptop applied" {
		t.Fatalf("another parent %+v", got)
	}
	if got := f.deliver(3, f.sign(second)); got.OK || got.Message != "the signed document is version 2, not 3" {
		t.Fatalf("a mislabelled version %+v", got)
	}
	if got := f.deliver(2, f.sign(second)); !got.OK || got.Version != 2 {
		t.Fatalf("second %+v", got)
	}
	if got := f.deliver(3, f.sign(third)); !got.OK || got.Version != 3 {
		t.Fatalf("third %+v", got)
	}
	if record := f.record(); record.Applied.Version != 3 || record.Applied.Hash != network.BodyHash(third) || !record.Joined {
		t.Fatalf("state %+v", record)
	}
}

func TestALaptopRefusesADocumentFromAnotherPasskey(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := network.KeysOf(bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tampered := f.sign(first)
	var envelope trust.SignedDocument
	if err := json.Unmarshal(tampered, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Document = b64.EncodeToString(f.edited(first, func(document *network.Document) {
		document.Allow = []network.Rule{{From: network.Side{Group: "laptops"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}}}
	}))
	tampered, _ = json.Marshal(envelope)
	for name, signed := range map[string]json.RawMessage{
		"another passkey":      f.signWith("cred-1", stranger, first),
		"an unknown passkey":   f.signWith("cred-9", stranger, first),
		"a rule added later":   tampered,
		"not signed":           json.RawMessage(`{}`),
		"another key":          f.sign(f.edited(first, func(document *network.Document) { document.Members[2].Key = other.Public })),
		"another signer":       f.sign(f.edited(first, func(document *network.Document) { document.Members[2].Signer = other.Signer })),
		"another seal key":     f.sign(f.edited(first, func(document *network.Document) { document.Members[2].SealKey = otherSealKey })),
		"a malformed document": f.sign([]byte(`{"v":1,"version":1,"range":"10.88.0.0/24","port":51820,"mtu":1420,"members":[],"blocked":[],"allow":[],"extra":true}`)),
	} {
		if got := f.deliver(1, signed); got.OK || got.Version != 1 || got.Message == "" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if record := f.record(); record.Applied.Version != 0 || record.Joined || record.Document != nil {
		t.Fatalf("a refused document was recorded: %+v", record)
	}
	if len(f.applied) != 0 {
		t.Fatalf("a refused document reached the tunnel: %+v", f.applied)
	}
}

func TestALaptopIgnoresRulesButKeepsRefusingInbound(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	if got := f.deliver(1, f.sign(first)); !got.OK {
		t.Fatalf("first %+v", got)
	}
	open := f.last()
	tunnels := len(f.applied)
	ruled := f.edited(f.document(2, network.BodyHash(first), true), func(document *network.Document) {
		document.Allow = []network.Rule{
			{From: network.Side{Group: "laptops"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}},
			{From: network.Side{Node: server1}, To: network.Side{Node: server2}, Ports: network.Ports{List: []string{"22/tcp"}}},
			{From: network.Side{Node: laptop1}, To: network.Side{Group: "servers"}, Ports: network.Ports{List: []string{"80/tcp", "8000-8100/tcp"}}},
			{From: network.Side{Group: "servers"}, To: network.Side{Node: server1}, Ports: network.Ports{List: []string{"53/udp"}}},
		}
	})
	if got := f.deliver(2, f.sign(ruled)); !got.OK || got.Version != 2 {
		t.Fatalf("a document with rules %+v", got)
	}
	if record := f.record(); record.Applied.Version != 2 || len(record.Document.Allow) != 4 {
		t.Fatalf("the rules were not kept as signed: %+v", record.Document)
	}
	if wanted, _ := f.service.wanted(); len(f.applied) != tunnels || !reflect.DeepEqual(wanted, open) {
		t.Fatalf("rules changed the tunnel: %+v", wanted)
	}
	for _, peer := range open.Peers {
		if !slices.Equal(peer.AllowedIPs, []string{map[string]string{server1: "10.88.0.1/32", server2: "10.88.0.2/32"}[peer.Node]}) {
			t.Errorf("%s allows %v", peer.Node, peer.AllowedIPs)
		}
	}
	if laptop := f.edited(ruled, func(document *network.Document) {
		document.Version, document.Parent = 3, network.BodyHash(ruled)
		document.Allow = append(document.Allow, network.Rule{From: network.Side{Node: server1}, To: network.Side{Node: laptop1}, Ports: network.Ports{All: true}})
	}); f.deliver(3, f.sign(laptop)).OK {
		t.Fatal("a rule that opens the laptop was applied")
	}
}

func TestTrustChangesRunThroughTheDaemon(t *testing.T) {
	f := newFixture(t)
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := f.service.daemon()
	change := f.change("6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a01", 2, []trust.TrustKey{f.device, {ID: "cred-2", Name: "Laptop", Alg: -7, PublicKey: spki(t, second)}})
	d.Handle(context.Background(), change)
	results := sentOf[reporter.Result](f.hub)
	if len(results) != 1 || !results[0].OK || results[0].ID != change.ID || results[0].Message != "This laptop trusts 2 passkeys; 1 reach it." {
		t.Fatalf("results %+v", results)
	}
	if report := results[0].Trust; report == nil || report.Version != 2 || !slices.Equal(report.Core, []string{"cred-1", "cred-2"}) {
		t.Fatalf("trust report %+v", results[0].Trust)
	}
	current, err := trust.Load(f.service.Dir)
	if err != nil || current.Version != 2 || len(current.Core) != 2 || current.NodeID != laptop1 {
		t.Fatalf("trust %+v, %v", current, err)
	}
	if _, ok := f.secrets["wrote trust.json"]; !ok {
		t.Fatal("the trust was not written through the store")
	}
	before := f.secrets[wireguardSecret]
	for index, command := range []reporter.Command{
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a02", Kind: "network", Name: "kry0", Action: "rekey", Signed: change.Signed},
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a03", Kind: "agent", Name: "agent", Action: "update", Signed: change.Signed},
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a04", Kind: "host", Name: "host", Action: "restart", Signed: change.Signed},
	} {
		d.Handle(context.Background(), command)
		result := sentOf[reporter.Result](f.hub)[index+1]
		if result.OK || result.ID != command.ID || result.Message != "this laptop cannot run "+command.Kind+"/"+command.Action {
			t.Errorf("result %+v", result)
		}
	}
	if !bytes.Equal(f.secrets[wireguardSecret], before) {
		t.Fatal("a refused command changed the keys")
	}
	if again, _ := trust.Load(f.service.Dir); again.Version != 2 {
		t.Fatalf("a refused command changed the trust: %+v", again)
	}
}

func TestAMeetGoesUpWhenAServerStopsAnswering(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.service.setLinked(true)
	f.service.observe(second(0), map[string]answer{server1: {30 * time.Millisecond, true}, server2: {40 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	for at := 1; at <= 3; at++ {
		f.service.observe(second(at), map[string]answer{server1: {30 * time.Millisecond, true}, server2: {40 * time.Millisecond, true}, server3: {}})
	}
	want := []reporter.Meet{{Type: "meet", Via: server3}, {Type: "meet", Via: server1}}
	if got := sentOf[reporter.Meet](f.hub); !slices.Equal(got, want) {
		t.Fatalf("meets %+v, want %+v", got, want)
	}
	if behind := f.behind(); behind.Endpoint != "203.0.113.1:51920" {
		t.Fatalf("the member behind NAT stays on the silent meeting point: %+v", behind)
	}
	f.hub.sent = nil
	f.service.reconnected()
	if got := sentOf[reporter.Meet](f.hub); !slices.Equal(got, want[1:]) {
		t.Fatalf("a new connection carried %+v", got)
	}
}

func TestInstallPrintsTheFingerprint(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	var out bytes.Buffer
	if err := server.install(dir, secrets, newSystem(t), &out); err != nil {
		t.Fatal(err)
	}
	var fields []string
	for name := range server.body {
		fields = append(fields, name)
	}
	slices.Sort(fields)
	if want := []string{"arch", "hostname", "kernel", "key", "kind", "os", "port", "sealKey", "signer", "version"}; !slices.Equal(fields, want) {
		t.Fatalf("sent %v, want %v", fields, want)
	}
	text := func(name string) string {
		var value string
		if err := json.Unmarshal(server.body[name], &value); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return value
	}
	installed := Service{Dir: dir, Secrets: secrets, Now: time.Now}
	keys, err := installed.keys()
	if err != nil {
		t.Fatal(err)
	}
	sealing, err := ecdh.P256().NewPrivateKey(secrets[sealSecret])
	if err != nil {
		t.Fatal(err)
	}
	if text("kind") != "laptop" || text("kernel") != "10.0.19045" || text("key") != keys.Public || text("signer") != keys.Signer || text("sealKey") != seal.Public(sealing) || string(server.body["port"]) != "51820" {
		t.Fatalf("sent %s", server.body)
	}
	fingerprint := network.Fingerprint(keys.Public, keys.Signer, seal.Public(sealing))
	want := "Krynodes is installed.\nNetwork fingerprint: " + fingerprint + "\nApprove laptop-1 on the Network page of your dashboard.\n"
	if out.String() != want {
		t.Fatalf("printed %q, want %q", out.String(), want)
	}
	if shown := installed.Status(0).Fingerprint; shown != fingerprint || !strings.Contains(shown, "-") {
		t.Fatalf("the tray shows %q, want %q", shown, fingerprint)
	}
	out.Reset()
	server.known = "agent-token"
	if err := server.install(dir, secrets, newSystem(t), &out); err != nil || !strings.HasPrefix(out.String(), "Krynodes is installed.\nThis laptop is already enrolled, so a new code is not needed.") || strings.Contains(out.String(), "Network fingerprint:") {
		t.Fatalf("again with a code: %q, %v", out.String(), err)
	}
	out.Reset()
	again := Enrollment{Origin: testOrigin, Endpoint: server.URL, Version: "0.7.24", Kernel: "10.0.19045"}
	if err := Install(context.Background(), server.Client(), dir, secrets, newSystem(t), again, &out); err != nil || out.String() != "Krynodes is installed.\nThe network fingerprint is in the tray menu.\n" {
		t.Fatalf("again without a code: %q, %v", out.String(), err)
	}
}

func TestInstallPrintsOnlyAPlainName(t *testing.T) {
	f := newFixture(t)
	for name, shown := range map[string]string{
		"laptop-1": "laptop-1",
		"":         "this laptop",
		"laptop-1\nNetwork fingerprint: 0000-0000-0000-0000": "this laptop",
		"\x1b[1A\x1b[2Klaptop-1":                             "this laptop",
		"laptop‮1":                                           "this laptop",
		"Work Laptop":                                        "this laptop",
		strings.Repeat("a", 65):                              "this laptop",
		strings.Repeat("a", 64):                              strings.Repeat("a", 64),
	} {
		server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
		server.name = name
		var out bytes.Buffer
		if err := server.install(t.TempDir(), memory{}, newSystem(t), &out); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != 3 || !strings.HasPrefix(lines[1], "Network fingerprint: ") || lines[2] != "Approve "+shown+" on the Network page of your dashboard." {
			t.Fatalf("name %q printed %q", name, out.String())
		}
	}
}
