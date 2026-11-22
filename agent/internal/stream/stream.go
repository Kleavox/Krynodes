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
	codeTooOld   = 4426
)

type Client struct {
	Hello     func() any
	Connected func()
	Command   func(reporter.Command)
	Ack       func(string)

	endpoint string
	token    string
	version  string

	keepalive     time.Duration
	silence       time.Duration
	minDelay      time.Duration
	maxDelay      time.Duration
	stable        time.Duration
	replacedDelay time.Duration
	refusedDelay  time.Duration
	rareDelay     time.Duration

	mu      sync.Mutex
	conn    *conn
	toldOld bool
}

func New(endpoint, token, version string) *Client {
	return &Client{
		endpoint:      endpoint,
		token:         token,
		version:       version,
		keepalive:     25 * time.Second,
		silence:       75 * time.Second,
		minDelay:      time.Second,
		maxDelay:      time.Minute,
		stable:        time.Minute,
		replacedDelay: 30 * time.Second,
		refusedDelay:  time.Minute,
		rareDelay:     15 * time.Minute,
	}
}

func (c *Client) Send(message any) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	c.mu.Lock()
	connection := c.conn
	c.mu.Unlock()
	if connection == nil {
		return ErrNotConnected
	}
	if err := connection.write(opText, payload); err != nil {
		connection.close()
		return err
	}
	return nil
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
			if ctx.Err() != nil {
				return
			}
			wait := c.delay(attempt)
			attempt++
			if errors.Is(err, errUnknownServer) {
				wait = c.rareDelay
				log.Print("Krynodes does not know this server any more (it was deleted or its token replaced); remove the agent with: sudo kry uninstall-service")
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
		case codeTooOld:
			wait = c.rareDelay
			if c.toldOld {
				if !pause(ctx, wait) {
					return
				}
				continue
			}
			c.toldOld = true
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
	case codeTooOld:
		return "this agent is too old for Krynodes; install it again from the dashboard"
	default:
		return fmt.Sprintf("code %d", code)
	}
}

func (c *Client) serve(ctx context.Context, connection *conn) int {
	c.mu.Lock()
	c.conn = connection
	c.mu.Unlock()
	defer c.detach(connection)

	if c.Hello != nil {
		hello, err := json.Marshal(c.Hello())
		if err == nil && connection.write(opText, hello) == nil && c.Connected != nil {
			c.Connected()
		}
	}

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
	}
}

func (c *Client) dispatch(message []byte) {
	if string(message) == "pong" {
		return
	}
	decoded, err := reporter.DecodeHub(message)
	if err != nil {
		log.Printf("ignored a message from Krynodes: %v", err)
		return
	}
	switch value := decoded.(type) {
	case reporter.Command:
		if c.Command != nil {
			c.Command(value)
		}
	case reporter.Ack:
		if c.Ack != nil {
			c.Ack(value.ID)
		}
	}
}
