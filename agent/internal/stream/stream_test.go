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
	"net"
	"net/http"
	"net/http/httptest"
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

func (p *peer) answer(id json.RawMessage, body string) {
	p.write(opText, []byte(`{"id":`+string(id)+`,`+body+`}`), true)
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

func client(t *testing.T, url string) (*Client, context.CancelFunc) {
	t.Helper()
	c := New(url, "token", "0.3.1")
	c.minDelay = 10 * time.Millisecond
	c.maxDelay = 40 * time.Millisecond
	c.replacedDelay = 300 * time.Millisecond
	c.refusedDelay = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	t.Cleanup(cancel)
	if err := c.WaitConnected(context.Background(), 2*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return c, cancel
}

func serveCalls(p *peer) {
	for {
		message, err := p.request()
		if err != nil {
			return
		}
		switch string(message["type"]) {
		case `"heartbeat"`:
			p.answer(message["id"], `"type":"heartbeat","response":{"ok":true,"intervalSeconds":60,"configVersion":"v1","refresh":true}`)
		case `"config"`:
			p.answer(message["id"], `"type":"config","config":{"nodeId":"node-1","intervalSeconds":60,"checks":[],"configVersion":"v1"}`)
		case `"actions"`:
			p.answer(message["id"], `"type":"actions","response":{"ok":true,"inventoryHash":"abc"}`)
		default:
			p.answer(message["id"], `"type":"error","code":"INVALID_MESSAGE"`)
		}
	}
}

func beat() reporter.Heartbeat {
	return reporter.Heartbeat{NodeID: "node-1", Host: reporter.Host{Hostname: "pivox", AgentVersion: "0.3.1"}}
}

func TestEveryCallSharesTheConnectionAndFindsItsAnswer(t *testing.T) {
	srv, dials := server(t, serveCalls)
	c, _ := client(t, srv.URL)
	var wait sync.WaitGroup
	errs := make(chan error, 3)
	wait.Add(3)
	go func() {
		defer wait.Done()
		response, err := c.SendHeartbeat(context.Background(), beat())
		if err == nil && (!response.Refresh || response.ConfigVersion != "v1") {
			err = errors.New("wrong heartbeat answer")
		}
		errs <- err
	}()
	go func() {
		defer wait.Done()
		config, err := c.FetchConfig(context.Background())
		if err == nil && config.NodeID != "node-1" {
			err = errors.New("wrong config answer")
		}
		errs <- err
	}()
	go func() {
		defer wait.Done()
		response, err := c.PostActions(context.Background(), reporter.ActionsReport{NodeID: "node-1"})
		if err == nil && (response.InventoryHash == nil || *response.InventoryHash != "abc") {
			err = errors.New("wrong actions answer")
		}
		errs <- err
	}()
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("dialled %d times", dials.Load())
	}
}

func TestAnErrorAnswerIsAnError(t *testing.T) {
	srv, _ := server(t, func(p *peer) {
		message, err := p.request()
		if err != nil {
			return
		}
		p.answer(message["id"], `"type":"error","code":"SERVER_ERROR"`)
		p.request()
	})
	c, _ := client(t, srv.URL)
	if _, err := c.SendHeartbeat(context.Background(), beat()); err == nil || !strings.Contains(err.Error(), "SERVER_ERROR") {
		t.Fatalf("err %v", err)
	}
}

func TestPokesArriveEvenInFragmentsAndPingsAreAnswered(t *testing.T) {
	pong := make(chan []byte, 1)
	srv, _ := server(t, func(p *peer) {
		p.write(opText, []byte(`{"type":`), false)
		p.write(opContinuation, []byte(`"poke"}`), true)
		p.write(opPing, []byte("hi"), true)
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
	c, _ := client(t, srv.URL)
	select {
	case <-c.Pokes():
	case <-time.After(2 * time.Second):
		t.Fatal("no poke")
	}
	select {
	case payload := <-pong:
		if string(payload) != "hi" {
			t.Fatalf("pong %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pong")
	}
}

func TestItReconnectsAtOnceAfterTheServerCloses(t *testing.T) {
	var first atomic.Bool
	srv, dials := server(t, func(p *peer) {
		if first.CompareAndSwap(false, true) {
			p.write(opClose, []byte{0x03, 0xe9}, true)
			return
		}
		serveCalls(p)
	})
	c, _ := client(t, srv.URL)
	deadline := time.Now().Add(2 * time.Second)
	for dials.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := c.WaitConnected(context.Background(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendHeartbeat(context.Background(), beat()); err != nil {
		t.Fatalf("after reconnect: %v", err)
	}
	ready := 0
	for drained := false; !drained; {
		select {
		case <-c.Ready():
			ready++
		default:
			drained = true
		}
	}
	if ready == 0 {
		t.Fatal("a reconnect should signal ready")
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
	c := New(srv.URL, "token", "0.3.1")
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
	c := New(srv.URL, "token", "0.3.1")
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

func TestCallsFailFastWithoutAConnection(t *testing.T) {
	c := New("http://127.0.0.1:1", "token", "0.3.1")
	if _, err := c.SendHeartbeat(context.Background(), beat()); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err %v", err)
	}
	if err := c.WaitConnected(context.Background(), 20*time.Millisecond); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("wait %v", err)
	}
}

func TestTheHandshakeMustProveTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, _ := w.(http.Hijacker).Hijack()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n")
		rw.Flush()
		conn.Close()
	}))
	defer srv.Close()
	if _, err := dial(context.Background(), srv.URL, "token", "0.3.1"); err == nil || !strings.Contains(err.Error(), "accept") {
		t.Fatalf("err %v", err)
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
	c := New(srv.URL, "token", "0.3.1")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(stopped)
	}()
	if err := c.WaitConnected(context.Background(), 2*time.Second); err != nil {
		t.Fatal(err)
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
