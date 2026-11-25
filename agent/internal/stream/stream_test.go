package stream

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type peer struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex
}

func (p *peer) read() (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(p.rw, header); err != nil {
		return 0, nil, err
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		extended := make([]byte, 2)
		io.ReadFull(p.rw, extended)
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		io.ReadFull(p.rw, extended)
		length = binary.BigEndian.Uint64(extended)
	}
	mask := make([]byte, 4)
	if header[1]&0x80 == 0 {
		return 0, nil, errors.New("client frame is not masked")
	}
	io.ReadFull(p.rw, mask)
	payload := make([]byte, length)
	if _, err := io.ReadFull(p.rw, payload); err != nil {
		return 0, nil, err
	}
	for index := range payload {
		payload[index] ^= mask[index%4]
	}
	return header[0] & 0x0f, payload, nil
}

func (p *peer) request() (map[string]json.RawMessage, error) {
	for {
		opcode, payload, err := p.read()
		if err != nil {
			return nil, err
		}
		if opcode != opText || string(payload) == "ping" {
			continue
		}
		var message map[string]json.RawMessage
		if err := json.Unmarshal(payload, &message); err != nil {
			return nil, err
		}
		return message, nil
	}
}

func (p *peer) write(opcode byte, payload []byte, fin bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first}
	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		extended := make([]byte, 8)
		binary.BigEndian.PutUint64(extended, uint64(len(payload)))
		frame = append(append(frame, 127), extended...)
	}
	p.rw.Write(append(frame, payload...))
	p.rw.Flush()
}

func server(t *testing.T, handle func(*peer)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dials.Add(1)
		if r.URL.Path != "/api/agent/stream" || r.Header.Get("Authorization") != "Bearer token" ||
			!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + guid))
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
		rw.WriteString("Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		rw.Flush()
		go func() {
			defer conn.Close()
			handle(&peer{conn: conn, rw: rw})
		}()
	}))
	t.Cleanup(srv.Close)
	return srv, &dials
}

type seen struct {
	connected chan struct{}
	commands  chan reporter.Command
	acks      chan string
}

func client(t *testing.T, url string) (*Client, *seen) {
	t.Helper()
	c, events := fresh(url)
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	t.Cleanup(cancel)
	select {
	case <-events.connected:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	return c, events
}

func fresh(url string) (*Client, *seen) {
	events := &seen{connected: make(chan struct{}, 8), commands: make(chan reporter.Command, 8), acks: make(chan string, 8)}
	c := New(url, "token", "0.7.90")
	c.minDelay = 10 * time.Millisecond
	c.maxDelay = 40 * time.Millisecond
	c.replacedDelay = 300 * time.Millisecond
	c.refusedDelay = 300 * time.Millisecond
	c.Hello = func() any { return reporter.Hello{Type: "hello", V: 1, Version: "0.7.90"} }
	c.Connected = func() { events.connected <- struct{}{} }
	c.Command = func(command reporter.Command) { events.commands <- command }
	c.Ack = func(id string) { events.acks <- id }
	return c, events
}

func drain(p *peer) {
	for {
		if _, _, err := p.read(); err != nil {
			return
		}
	}
}

func TestHelloGoesFirstThenWhatConnectedSends(t *testing.T) {
	got := make(chan []string, 1)
	srv, _ := server(t, func(p *peer) {
		var types []string
		for len(types) < 2 {
			message, err := p.request()
			if err != nil {
				return
			}
			types = append(types, string(message["type"]))
		}
		got <- types
		drain(p)
	})
	c, events := fresh(srv.URL)
	c.Connected = func() {
		c.Send(reporter.Result{Type: "result", ID: "r-1", OK: true, Message: "Restarting now."})
		events.connected <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	select {
	case types := <-got:
		if types[0] != `"hello"` || types[1] != `"result"` {
			t.Fatalf("sent %v", types)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing arrived")
	}
}

func TestCommandsAndAcksArriveDecodedAndAnythingElseIsDropped(t *testing.T) {
	pong := make(chan []byte, 1)
	srv, _ := server(t, func(p *peer) {
		p.write(opText, []byte(`{"TYPE":"ack","id":"x-1"}`), true)
		p.write(opText, []byte(`{"type":"ack","id":"x-2","extra":1}`), true)
		p.write(opText, []byte(`{"type":"poke"}`), true)
		p.write(opText, []byte(`{"type":"command","id":"c-1",`), false)
		p.write(opContinuation, []byte(`"kind":"host","name":"server-1","action":"restart","signed":"s"}`), true)
		p.write(opPing, []byte("hi"), true)
		p.write(opText, []byte(`{"type":"ack","id":"r-1"}`), true)
		for {
			opcode, payload, err := p.read()
			if err != nil {
				return
			}
			if opcode == opPong {
				pong <- payload
			}
		}
	})
	_, events := client(t, srv.URL)
	select {
	case command := <-events.commands:
		if command != (reporter.Command{Type: "command", ID: "c-1", Kind: "host", Name: "server-1", Action: "restart", Signed: "s"}) {
			t.Fatalf("command %+v", command)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no command")
	}
	select {
	case id := <-events.acks:
		if id != "r-1" {
			t.Fatalf("ack %q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ack")
	}
	select {
	case payload := <-pong:
		if string(payload) != "hi" {
			t.Fatalf("pong %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pong")
	}
	select {
	case id := <-events.acks:
		t.Fatalf("a second ack %q", id)
	case command := <-events.commands:
		t.Fatalf("a second command %+v", command)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestFramesThatBreakTheProtocolDeliverNothing(t *testing.T) {
	const ack = `{"type":"ack","id":"a-1"}`
	for name, send := range map[string]func(p *peer){
		"a message inside a message": func(p *peer) {
			p.write(opText, []byte(`{"type":`), false)
			p.write(opText, []byte(ack), true)
		},
		"a long ping": func(p *peer) {
			p.write(opPing, make([]byte, 126), true)
			p.write(opText, []byte(ack), true)
		},
		"a split ping": func(p *peer) {
			p.write(opPing, []byte("hi"), false)
			p.write(opText, []byte(ack), true)
		},
	} {
		srv, _ := server(t, func(p *peer) {
			send(p)
			drain(p)
		})
		_, events := client(t, srv.URL)
		select {
		case <-events.acks:
			t.Fatalf("%s: the connection went on", name)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func TestItReconnectsAtOnceAfterTheServerClosesAndSaysHelloAgain(t *testing.T) {
	var first atomic.Bool
	hellos := make(chan struct{}, 4)
	srv, dials := server(t, func(p *peer) {
		message, err := p.request()
		if err != nil || string(message["type"]) != `"hello"` {
			return
		}
		hellos <- struct{}{}
		if first.CompareAndSwap(false, true) {
			p.write(opClose, []byte{0x03, 0xe9}, true)
			return
		}
		drain(p)
	})
	_, events := client(t, srv.URL)
	for range 2 {
		select {
		case <-hellos:
		case <-time.After(2 * time.Second):
			t.Fatal("no hello")
		}
	}
	select {
	case <-events.connected:
	case <-time.After(2 * time.Second):
		t.Fatal("no second connection")
	}
	if dials.Load() != 2 {
		t.Fatalf("dials %d", dials.Load())
	}
}

func TestSilenceDropsAHalfOpenConnection(t *testing.T) {
	pings := make(chan struct{}, 8)
	srv, dials := server(t, func(p *peer) {
		for {
			opcode, payload, err := p.read()
			if err != nil {
				return
			}
			if opcode == opText && string(payload) == "ping" {
				pings <- struct{}{}
			}
		}
	})
	c := New(srv.URL, "token", "0.7.90")
	c.minDelay = 10 * time.Millisecond
	c.maxDelay = 40 * time.Millisecond
	c.keepalive = 20 * time.Millisecond
	c.silence = 70 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	select {
	case <-pings:
	case <-time.After(2 * time.Second):
		t.Fatal("no keepalive ping")
	}
	deadline := time.Now().Add(3 * time.Second)
	for dials.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dials.Load() < 2 {
		t.Fatal("a silent connection should be dropped and dialled again")
	}
}

func TestAReplacedConnectionWaitsBeforeComingBack(t *testing.T) {
	var times []time.Time
	var mu sync.Mutex
	srv, _ := server(t, func(p *peer) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		p.write(opClose, []byte{0x0f, 0xa0}, true)
	})
	c := New(srv.URL, "token", "0.7.90")
	c.minDelay = 10 * time.Millisecond
	c.maxDelay = 40 * time.Millisecond
	c.replacedDelay = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(times)
		mu.Unlock()
		if count >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(times) < 2 || times[1].Sub(times[0]) < 250*time.Millisecond {
		t.Fatalf("replaced connection came back too soon: %v", times)
	}
}

func TestADeletedServerAsksAgainOnlyRarely(t *testing.T) {
	for status, slow := range map[int]bool{http.StatusUnauthorized: true, http.StatusBadGateway: false} {
		var times []time.Time
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			times = append(times, time.Now())
			mu.Unlock()
			w.WriteHeader(status)
		}))
		c := New(srv.URL, "token", "0.7.90")
		c.minDelay = 10 * time.Millisecond
		c.maxDelay = 40 * time.Millisecond
		c.rareDelay = 400 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		go c.Run(ctx)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			count := len(times)
			mu.Unlock()
			if count >= 2 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		srv.Close()
		mu.Lock()
		if len(times) < 2 || (times[1].Sub(times[0]) >= 350*time.Millisecond) != slow {
			t.Fatalf("HTTP %d: dials %v", status, times)
		}
		mu.Unlock()
	}
}

func TestSendFailsFastWithoutAConnection(t *testing.T) {
	c := New("http://127.0.0.1:1", "token", "0.7.90")
	if err := c.Send(reporter.Ack{Type: "ack", ID: "a"}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err %v", err)
	}
}

func TestATooOldAgentAsksAgainOnlyRarelyAndSaysWhyOnce(t *testing.T) {
	var times []time.Time
	var mu sync.Mutex
	srv, _ := server(t, func(p *peer) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		p.write(opClose, []byte{0x11, 0x4a}, true)
		drain(p)
	})
	var logged strings.Builder
	var logMu sync.Mutex
	log.SetOutput(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logged.Write(b)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	c, _ := fresh(srv.URL)
	c.rareDelay = 150 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(times)
		mu.Unlock()
		if count >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if len(times) < 3 || times[1].Sub(times[0]) < 120*time.Millisecond || times[2].Sub(times[1]) < 120*time.Millisecond {
		t.Fatalf("dials %v", times)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if strings.Count(logged.String(), "too old") != 1 {
		t.Fatalf("logged: %s", logged.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestTheHandshakeMustProveTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, _ := w.(http.Hijacker).Hijack()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n")
		rw.Flush()
		conn.Close()
	}))
	defer srv.Close()
	if _, err := dial(context.Background(), srv.URL, "token", "0.7.90"); err == nil || !strings.Contains(err.Error(), "accept") {
		t.Fatalf("err %v", err)
	}
}

func TestStoppingDuringAHangingDialReturnsAtOnce(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c, _ := fresh(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(stopped)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Run kept waiting on a dial after its context ended")
	}
}

func TestRunSaysGoodbyeBeforeItReturns(t *testing.T) {
	goodbye := make(chan []byte, 1)
	srv, _ := server(t, func(p *peer) {
		for {
			opcode, payload, err := p.read()
			if err != nil {
				return
			}
			if opcode == opClose {
				goodbye <- payload
				return
			}
		}
	})
	c, events := fresh(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(stopped)
	}()
	select {
	case <-events.connected:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Run kept going after its context ended")
	}
	select {
	case payload := <-goodbye:
		if len(payload) < 2 || payload[0] != 0x03 || payload[1] != 0xe8 {
			t.Fatalf("close payload %v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server never saw a close frame")
	}
}

func TestTheStreamNeedsTLS13(t *testing.T) {
	transport := dialer.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("the stream must need TLS 1.3")
	}
}

func TestNetworkMessagesArriveDecoded(t *testing.T) {
	srv, _ := server(t, func(p *peer) {
		p.write(opText, []byte(`{"type":"refresh"}`), true)
		p.write(opText, []byte(`{"type":"hints","endpoints":[],"announced":[],"meetings":[{"laptop":"laptop-1","via":"server-2"}],"held":["server-1"],"connected":[]}`), true)
		p.write(opText, []byte(`{"type":"document","version":3,"signed":"s"}`), true)
		drain(p)
	})
	c, events := fresh(srv.URL)
	arrived := make(chan any, 8)
	c.Network = func(message any) { arrived <- message }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	<-events.connected
	var got []any
	for len(got) < 3 {
		select {
		case message := <-arrived:
			got = append(got, message)
		case <-time.After(2 * time.Second):
			t.Fatalf("arrived %+v", got)
		}
	}
	hints, ok := got[1].(reporter.Hints)
	if got[0] != (reporter.Refresh{Type: "refresh"}) || !ok || len(hints.Meetings) != 1 || hints.Meetings[0].Via != "server-2" || len(hints.Held) != 1 || got[2] != (reporter.Document{Type: "document", Version: 3, Signed: "s"}) {
		t.Fatalf("arrived %+v", got)
	}
}

func TestTheChosenChecksArriveDecoded(t *testing.T) {
	srv, _ := server(t, func(p *peer) {
		p.write(opText, []byte(`{"type":"checks","names":["bad/name"]}`), true)
		p.write(opText, []byte(`{"type":"checks","names":["web-1","web-2"]}`), true)
		drain(p)
	})
	c, events := fresh(srv.URL)
	arrived := make(chan reporter.Checks, 4)
	c.Checks = func(checks reporter.Checks) { arrived <- checks }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	<-events.connected
	select {
	case checks := <-arrived:
		if checks.Type != "checks" || len(checks.Names) != 2 || checks.Names[0] != "web-1" || checks.Names[1] != "web-2" {
			t.Fatalf("arrived %+v", checks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the checks did not arrive")
	}
}

func TestHelloAgainGoesOutOnTheLiveConnection(t *testing.T) {
	got := make(chan []string, 1)
	srv, dials := server(t, func(p *peer) {
		var types []string
		for len(types) < 2 {
			message, err := p.request()
			if err != nil {
				return
			}
			types = append(types, string(message["type"]))
		}
		got <- types
		drain(p)
	})
	c, _ := client(t, srv.URL)
	if err := c.HelloAgain(); err != nil {
		t.Fatal(err)
	}
	select {
	case types := <-got:
		if types[0] != `"hello"` || types[1] != `"hello"` || dials.Load() != 1 {
			t.Fatalf("sent %v over %d connections", types, dials.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing arrived")
	}
	if idle, _ := fresh(srv.URL); !errors.Is(idle.HelloAgain(), ErrNotConnected) {
		t.Fatal("hello went out without a connection")
	}
}

func TestDisconnectedIsToldWhenTheConnectionCloses(t *testing.T) {
	closing := make(chan struct{})
	srv, _ := server(t, func(p *peer) {
		if _, err := p.request(); err != nil {
			return
		}
		<-closing
		p.write(opClose, []byte{0x11, 0x31}, true)
	})
	c, events := fresh(srv.URL)
	gone := make(chan struct{}, 8)
	c.Disconnected = func() { gone <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	select {
	case <-events.connected:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	select {
	case <-gone:
		t.Fatal("told disconnected on an open connection")
	default:
	}
	close(closing)
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Fatal("not told when the hub closed the connection")
	}
}
