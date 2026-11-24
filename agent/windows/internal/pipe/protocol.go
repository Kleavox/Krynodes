package pipe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/windows/internal/exit"
)

const (
	Path       = `\\.\pipe\krynodes`
	MaxRequest = 4 << 10
	MaxReply   = 1 << 20
	patience   = 5 * time.Second
	notAllowed = "not allowed"
)

type Settings struct {
	StartWithWindows *bool `json:"startWithWindows,omitempty"`
	NotifyOffline    *bool `json:"notifyOffline,omitempty"`
}

type Request struct {
	Request string  `json:"request"`
	Server  *string `json:"server,omitempty"`
	On      *bool   `json:"on,omitempty"`
	Seen    *uint64 `json:"seen,omitempty"`
	Settings
}

type Server struct {
	Node    string `json:"node"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Via     string `json:"via,omitempty"`
	Online  *bool  `json:"online,omitempty"`
	RTT     *int   `json:"rtt,omitempty"`
}

type Status struct {
	Joined           bool     `json:"joined"`
	Connected        bool     `json:"connected"`
	FirewallOff      bool     `json:"firewallOff"`
	Name             string   `json:"name"`
	Address          string   `json:"address"`
	Fingerprint      string   `json:"fingerprint"`
	Exit             string   `json:"exit"`
	Local            bool     `json:"local"`
	Exits            []Server `json:"exits"`
	Servers          []Server `json:"servers"`
	Dashboard        string   `json:"dashboard"`
	StartWithWindows bool     `json:"startWithWindows"`
	NotifyOffline    bool     `json:"notifyOffline"`
	Notes            []string `json:"notes"`
	Last             uint64   `json:"last"`
	Version          string   `json:"version"`
}

type Reply struct {
	OK     bool    `json:"ok,omitempty"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

type Backend interface {
	Status(seen uint64) Status
	Network() (network.Document, []string, bool)
	Connect(on bool) error
	Exit(server string) error
	Local(on bool) error
	Settings(Settings) error
	Update() error
}

var ErrNotOffered = errors.New("That server does not offer an exit node.")

func Handle(backend Backend, line []byte) Reply {
	refused := Reply{Error: notAllowed}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if len(line) > MaxRequest || decoder.Decode(&request) != nil || decoder.More() {
		return refused
	}
	if request.Seen != nil && request.Request != "status" {
		return refused
	}
	var err error
	switch request.Request {
	case "status":
		seen := uint64(0)
		if request.Seen != nil {
			seen = *request.Seen
		}
		status := backend.Status(seen)
		return Reply{OK: true, Status: &status}
	case "connect":
		err = backend.Connect(true)
	case "disconnect":
		err = backend.Connect(false)
	case "exit":
		server := ""
		if request.Server != nil {
			server = *request.Server
		}
		if server != "" {
			if document, held, ok := backend.Network(); !ok || !exit.Offered(document, held, server) {
				return Reply{Error: ErrNotOffered.Error()}
			}
		}
		err = backend.Exit(server)
	case "local":
		if request.On == nil {
			return refused
		}
		err = backend.Local(*request.On)
	case "settings":
		if request.StartWithWindows == nil && request.NotifyOffline == nil {
			return refused
		}
		err = backend.Settings(request.Settings)
	case "update":
		err = backend.Update()
	default:
		return refused
	}
	if err != nil {
		return Reply{Error: err.Error()}
	}
	return Reply{OK: true}
}

type Conn interface {
	io.ReadWriter
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func Converse(conn Conn, backend Backend, now func() time.Time) error {
	if err := conn.SetReadDeadline(now().Add(patience)); err != nil {
		return err
	}
	reply := Answer(conn, backend)
	if err := conn.SetWriteDeadline(now().Add(patience)); err != nil {
		return err
	}
	_, err := conn.Write(reply)
	return err
}

func Answer(conn io.Reader, backend Backend) []byte {
	line, err := bufio.NewReaderSize(conn, MaxRequest).ReadSlice('\n')
	reply := Reply{Error: notAllowed}
	if err == nil {
		reply = Handle(backend, line)
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		encoded = []byte(`{"error":"not allowed"}`)
	}
	return append(encoded, '\n')
}
