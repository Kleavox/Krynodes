package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var ErrNotConnected = errors.New("no live connection to Krynodes")

const (
	codeReplaced = 4000
	codeRefused  = 4401
)

type envelope struct {
	ID       uint64          `json:"id"`
	Type     string          `json:"type"`
	Code     string          `json:"code"`
	Response json.RawMessage `json:"response"`
	Config   json.RawMessage `json:"config"`
}

type Client struct {
	endpoint string
	token    string
	version  string

	keepalive     time.Duration
	silence       time.Duration
	reply         time.Duration
	minDelay      time.Duration
	maxDelay      time.Duration
	stable        time.Duration
	replacedDelay time.Duration
	refusedDelay  time.Duration
	goneDelay     time.Duration

	mu      sync.Mutex
	conn    *conn
	nextID  uint64
	waiting map[uint64]chan envelope
	up      chan struct{}
	ready   chan struct{}
	pokes   chan struct{}
}

func New(endpoint, token, version string) *Client {
	return &Client{
		endpoint:      endpoint,
		token:         token,
		version:       version,
		keepalive:     25 * time.Second,
		silence:       75 * time.Second,
		reply:         30 * time.Second,
		minDelay:      time.Second,
		maxDelay:      time.Minute,
		stable:        time.Minute,
		replacedDelay: 30 * time.Second,
		refusedDelay:  time.Minute,
		goneDelay:     15 * time.Minute,
		waiting:       map[uint64]chan envelope{},
		up:            make(chan struct{}),
		ready:         make(chan struct{}, 1),
		pokes:         make(chan struct{}, 1),
	}
}

func (c *Client) Ready() <-chan struct{} {
	return c.ready
}

func (c *Client) Pokes() <-chan struct{} {
	return c.pokes
}

func (c *Client) WaitConnected(ctx context.Context, limit time.Duration) error {
	c.mu.Lock()
	up := c.up
	c.mu.Unlock()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-up:
		return nil
	case <-timer.C:
		return ErrNotConnected
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) delay(attempt int) time.Duration {
	base := c.minDelay << min(attempt, 16)
	if base > c.maxDelay || base <= 0 {
		base = c.maxDelay
	}
	return base/2 + time.Duration(rand.Int64N(int64(base)+1))
}

func pause(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) Run(ctx context.Context) {
	attempt := 0
	for ctx.Err() == nil {
		connection, err := dial(ctx, c.endpoint, c.token, c.version)
		if err != nil {
			wait := c.delay(attempt)
			attempt++
			if errors.Is(err, errUnknownServer) {
				wait = c.goneDelay
				log.Printf("Krynodes does not know this server any more (it was deleted or its token replaced); remove the agent with: sudo kry uninstall-service")
			}
			log.Printf("live connection to Krynodes failed: %v; retrying in %s", err, wait.Round(time.Second))
			if !pause(ctx, wait) {
				return
			}
			continue
		}
		log.Printf("live connection to Krynodes open")
		opened := time.Now()
		code := c.serve(ctx, connection)
		if ctx.Err() != nil {
			return
		}
		if time.Since(opened) >= c.stable {
			attempt = 0
		}
		wait := c.delay(attempt)
		attempt++
		switch code {
		case codeReplaced:
			wait = max(wait, c.replacedDelay)
		case codeRefused:
			wait = max(wait, c.refusedDelay)
		}
		log.Printf("live connection to Krynodes closed (%s); reconnecting in %s", describe(code), wait.Round(time.Second))
		if !pause(ctx, wait) {
			return
		}
	}
}

func describe(code int) string {
	switch code {
	case 0:
		return "connection lost"
	case codeReplaced:
		return "another agent with this token connected"
	case codeRefused:
		return "the server is unknown or disabled"
	default:
		return fmt.Sprintf("code %d", code)
	}
}

func (c *Client) serve(ctx context.Context, connection *conn) int {
	c.mu.Lock()
	c.conn = connection
	close(c.up)
	c.mu.Unlock()
	select {
	case c.ready <- struct{}{}:
	default:
	}
	defer c.detach(connection)

	var lastRead atomic.Int64
	lastRead.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(c.keepalive)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				connection.close()
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastRead.Load())) > c.silence {
					log.Printf("live connection to Krynodes went silent")
					connection.close()
					return
				}
				if err := connection.write(opText, []byte("ping")); err != nil {
					connection.close()
					return
				}
			}
		}
	}()

	for {
		message, err := connection.readMessage()
		if err != nil {
			var closed *closeError
			if errors.As(err, &closed) {
				return closed.code
			}
			return 0
		}
		lastRead.Store(time.Now().UnixNano())
		c.dispatch(message)
	}
}

func (c *Client) detach(connection *conn) {
	connection.close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == connection {
		c.conn = nil
		c.up = make(chan struct{})
	}
	for id, waiter := range c.waiting {
		close(waiter)
		delete(c.waiting, id)
	}
}

func (c *Client) dispatch(message []byte) {
	var answer envelope
	if json.Unmarshal(message, &answer) != nil {
		return
	}
	if answer.Type == "poke" {
		select {
		case c.pokes <- struct{}{}:
		default:
		}
		return
	}
	c.mu.Lock()
	waiter, ok := c.waiting[answer.ID]
	delete(c.waiting, answer.ID)
	c.mu.Unlock()
	if ok {
		waiter <- answer
	}
}

func (c *Client) call(ctx context.Context, kind string, fields map[string]any) (envelope, error) {
	c.mu.Lock()
	connection := c.conn
	if connection == nil {
		c.mu.Unlock()
		return envelope{}, ErrNotConnected
	}
	c.nextID++
	id := c.nextID
	waiter := make(chan envelope, 1)
	c.waiting[id] = waiter
	c.mu.Unlock()
	forget := func() {
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
	}

	request := map[string]any{"id": id, "type": kind}
	for key, value := range fields {
		request[key] = value
	}
	payload, err := json.Marshal(request)
	if err != nil {
		forget()
		return envelope{}, err
	}
	if err := connection.write(opText, payload); err != nil {
		forget()
		connection.close()
		return envelope{}, fmt.Errorf("send %s: %w", kind, err)
	}
	timer := time.NewTimer(c.reply)
	defer timer.Stop()
	select {
	case answer, ok := <-waiter:
		if !ok {
			return envelope{}, fmt.Errorf("send %s: %w", kind, ErrNotConnected)
		}
		if answer.Type == "error" {
			return envelope{}, fmt.Errorf("Krynodes refused the %s: %s", kind, answer.Code)
		}
		if answer.Type != kind {
			return envelope{}, fmt.Errorf("Krynodes answered the %s with %q", kind, answer.Type)
		}
		return answer, nil
	case <-timer.C:
		forget()
		connection.close()
		return envelope{}, fmt.Errorf("Krynodes did not answer the %s", kind)
	case <-ctx.Done():
		forget()
		return envelope{}, ctx.Err()
	}
}

func (c *Client) SendHeartbeat(ctx context.Context, beat reporter.Heartbeat) (reporter.HeartbeatResponse, error) {
	var response reporter.HeartbeatResponse
	answer, err := c.call(ctx, "heartbeat", map[string]any{"heartbeat": beat})
	if err != nil {
		return response, err
	}
	return response, json.Unmarshal(answer.Response, &response)
}

func (c *Client) FetchConfig(ctx context.Context) (reporter.AgentConfig, error) {
	var config reporter.AgentConfig
	answer, err := c.call(ctx, "config", nil)
	if err != nil {
		return config, err
	}
	return config, json.Unmarshal(answer.Config, &config)
}

func (c *Client) PostActions(ctx context.Context, report reporter.ActionsReport) (reporter.ActionsResponse, error) {
	var response reporter.ActionsResponse
	answer, err := c.call(ctx, "actions", map[string]any{"report": report})
	if err != nil {
		return response, err
	}
	return response, json.Unmarshal(answer.Response, &response)
}
