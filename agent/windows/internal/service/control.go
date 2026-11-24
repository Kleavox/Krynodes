package service

import (
	"errors"
	"log"
	"slices"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/trust"
	"github.com/Kleavox/krynodes/agent/windows/internal/exit"
	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
)

const (
	keptNotes = 10
	noteKept  = time.Minute
)

var (
	errOff   = errors.New("Connect this laptop first.")
	errNoDNS = errors.New("The private network has no DNS for laptops, so the exit node stays off.")
)

type note struct {
	id   uint64
	line string
	at   time.Time
}

type health struct {
	watch exit.ExitWatch
	rtt   time.Duration
	seen  bool
	alive bool
}

func (s *Service) say(line string) {
	log.Print(line)
	now := s.Now()
	s.noteID = max(s.noteID+1, uint64(max(now.UnixNano(), 0)))
	s.notes = append(s.notes, note{id: s.noteID, line: line, at: now})
	if len(s.notes) > keptNotes {
		s.notes = slices.Clone(s.notes[len(s.notes)-keptNotes:])
	}
}

func (s *Service) listen(now time.Time, record state, answers map[string]answer) {
	if s.health == nil {
		s.health = map[string]*health{}
	}
	answered := false
	for _, got := range answers {
		answered = answered || got.ok
	}
	for node, got := range answers {
		entry := s.health[node]
		if entry == nil {
			entry = &health{}
			s.health[node] = entry
		}
		was := entry.seen && entry.alive
		entry.alive = entry.watch.Observe(now, got.ok, false)
		if got.ok {
			entry.rtt, entry.seen = got.rtt, true
		}
		if server, ok := member(*record.Document, node); ok && was && !entry.alive && record.Offline && answered {
			s.say(server.Name + " went offline.")
		}
	}
}

func (s *Service) Status(seen uint64) pipe.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := pipe.Status{Exit: s.last.Exit, Local: s.local, Last: s.noteID, Fingerprint: s.fingerprint(), Connected: !s.off}
	now := s.Now()
	s.notes = slices.DeleteFunc(s.notes, func(waiting note) bool { return now.Sub(waiting.at) > noteKept })
	for _, waiting := range s.notes {
		if waiting.id > seen {
			status.Notes = append(status.Notes, waiting.line)
		}
	}
	if trusted, err := trust.Load(s.Dir); err == nil {
		status.Dashboard = trusted.Origin
	}
	record, err := s.read()
	if err != nil {
		return status
	}
	status.Joined, status.NotifyOffline = record.Joined, record.Offline
	if record.Document == nil || !record.Joined {
		return status
	}
	document := *record.Document
	if self, ok := member(document, record.NodeID); ok {
		status.Name, status.Address = self.Name, self.Address
	}
	meeting, _ := member(document, meetingOf(document, s.meet, s.held))
	measured := len(s.last.Peers) > 0
	for _, entry := range reached(document, record.NodeID) {
		server := pipe.Server{Node: entry.Node, Name: entry.Name, Address: entry.Address}
		if entry.NAT {
			server.Via = meeting.Name
		}
		if known := s.health[entry.Node]; measured && known != nil && (known.seen || !known.alive) {
			online := known.alive
			server.Online = &online
			if online {
				rtt := int(known.rtt.Milliseconds())
				server.RTT = &rtt
			}
		}
		status.Servers = append(status.Servers, server)
		if exit.Offered(document, s.held, entry.Node) {
			status.Exits = append(status.Exits, server)
		}
	}
	return status
}

func (s *Service) Network() (network.Document, []string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil || record.Document == nil || !record.Joined {
		return network.Document{}, nil, false
	}
	return *record.Document, slices.Clone(s.held), true
}

func (s *Service) Connect(on bool) error {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.off != on {
		return nil
	}
	s.off = !on
	if !on {
		s.exit, s.watching, s.health = "", "", nil
	}
	s.refresh()
	return nil
}

func (s *Service) Exit(server string) error {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	if server != "" {
		record, err := s.read()
		switch {
		case err != nil || record.Document == nil || !record.Joined:
			return pipe.ErrNotOffered
		case s.off:
			return errOff
		case !exit.Offered(*record.Document, s.held, server):
			return pipe.ErrNotOffered
		}
	}
	s.exit = server
	s.refresh()
	if server != "" && s.exit == "" {
		return errNoDNS
	}
	return nil
}

func (s *Service) Local(on bool) error {
	defer s.push()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.local = on
	s.refresh()
	return nil
}

func (s *Service) NotifyOffline(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil {
		return err
	}
	record.Offline = on
	return s.save(record)
}
