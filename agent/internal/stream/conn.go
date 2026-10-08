package stream

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	guid           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	opContinuation = byte(0x0)
	opText         = byte(0x1)
	opBinary       = byte(0x2)
	opClose        = byte(0x8)
	opPing         = byte(0x9)
	opPong         = byte(0xa)
	maxMessage     = 1 << 20
)

type closeError struct{ code int }

func (e *closeError) Error() string {
	return fmt.Sprintf("closed with code %d", e.code)
}

type conn struct {
	rwc       io.ReadWriteCloser
	reader    *bufio.Reader
	writeMu   sync.Mutex
	closeOnce sync.Once
}

var errUnknownServer = errors.New("Krynodes refused this server's token (HTTP 401)")

var dialer = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       reporter.TLSConfig(),
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	},
}

func dial(ctx context.Context, endpoint, token, version string) (*conn, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)
	request, err := http.NewRequestWithContext(
		context.WithoutCancel(ctx),
		http.MethodGet,
		strings.TrimRight(endpoint, "/")+"/api/agent/stream",
		nil,
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "kry-agent/"+version)
	response, err := dialer.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		response.Body.Close()
		return nil, errUnknownServer
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		response.Body.Close()
		return nil, fmt.Errorf("live connection refused with HTTP %d", response.StatusCode)
	}
	sum := sha1.Sum([]byte(key + guid))
	if response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		response.Body.Close()
		return nil, errors.New("the server did not accept the connection key")
	}
	rwc, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		response.Body.Close()
		return nil, errors.New("the connection cannot be upgraded")
	}
	return &conn{rwc: rwc, reader: bufio.NewReader(rwc)}, nil
}

func (c *conn) write(opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		extended := make([]byte, 8)
		binary.BigEndian.PutUint64(extended, uint64(len(payload)))
		header = append(append(header, 0x80|127), extended...)
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	frame := make([]byte, 0, len(header)+4+len(payload))
	frame = append(append(frame, header...), mask...)
	for index, value := range payload {
		frame = append(frame, value^mask[index%4])
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.rwc.Write(frame)
	return err
}

func (c *conn) readFrame() (bool, byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return false, 0, nil, err
	}
	if header[1]&0x80 != 0 {
		return false, 0, nil, errors.New("the server masked a frame")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if length > maxMessage {
		return false, 0, nil, errors.New("the server sent a message that is too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return false, 0, nil, err
	}
	return header[0]&0x80 != 0, header[0] & 0x0f, payload, nil
}

func (c *conn) readMessage() ([]byte, error) {
	var message []byte
	reading := false
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case opPing:
			if err := c.write(opPong, payload); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			c.write(opClose, payload)
			code := 1005
			if len(payload) >= 2 {
				code = int(binary.BigEndian.Uint16(payload[:2]))
			}
			return nil, &closeError{code: code}
		case opText, opBinary:
			message = append([]byte(nil), payload...)
			reading = true
		case opContinuation:
			if !reading {
				return nil, errors.New("the server continued a message it never started")
			}
			message = append(message, payload...)
		default:
			return nil, fmt.Errorf("the server sent opcode %d", opcode)
		}
		if len(message) > maxMessage {
			return nil, errors.New("the server sent a message that is too large")
		}
		if fin {
			return message, nil
		}
	}
}

func (c *conn) close() {
	c.closeOnce.Do(func() {
		c.write(opClose, []byte{0x03, 0xe8})
		c.rwc.Close()
	})
}
