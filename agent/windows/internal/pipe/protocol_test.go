package pipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	server1 = "22222222-2222-4222-8222-222222222222"
	server2 = "33333333-3333-4333-8333-333333333333"
	server3 = "44444444-4444-4444-8444-444444444444"
	laptop1 = "11111111-1111-4111-8111-111111111111"
)

type fake struct {
	held  []string
	calls []string
	seen  []uint64
}

func endpoint(text string) *string {
	return &text
}

func (f *fake) Status(seen uint64) Status {
	f.calls = append(f.calls, "status")
	f.seen = append(f.seen, seen)
	return Status{Connected: true, Name: "laptop-1", Address: "10.88.0.10"}
}

func (f *fake) Network() (network.Document, []string, bool) {
	return network.Document{Members: []network.Member{
		{Node: server1, Name: "server-1", Address: "10.88.0.1", Endpoint: endpoint("203.0.113.1:51820"), Exit: true},
		{Node: server2, Name: "server-2", Address: "10.88.0.2", NAT: true},
		{Node: server3, Name: "server-3", Address: "10.88.0.3", Endpoint: endpoint("203.0.113.3:51820")},
		{Node: laptop1, Name: "laptop-1", Address: "10.88.0.10", Kind: "laptop"},
	}}, f.held, true
}

func (f *fake) Connect(on bool) error {
	f.calls = append(f.calls, map[bool]string{true: "connect", false: "disconnect"}[on])
	return nil
}

func (f *fake) Exit(server string) error {
	f.calls = append(f.calls, "exit "+server)
	return nil
}

func (f *fake) Local(on bool) error {
	f.calls = append(f.calls, map[bool]string{true: "local on", false: "local off"}[on])
	return nil
}

func (f *fake) Settings(settings Settings) error {
	f.calls = append(f.calls, "settings")
	return nil
}

func (f *fake) Update() error {
	f.calls = append(f.calls, "update")
	return errors.New("Updating the agent is not available yet.")
}

func ask(t *testing.T, backend Backend, line string) Reply {
	t.Helper()
	var reply Reply
	raw := Answer(strings.NewReader(line), backend)
	if !bytes.HasSuffix(raw, []byte("\n")) || bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("%q is not one line", raw)
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestThePipeRefusesEveryOtherRequest(t *testing.T) {
	f := &fake{}
	for _, line := range []string{
		`{"request":"trust"}` + "\n",
		`{"request":"join"}` + "\n",
		`{"request":"document"}` + "\n",
		`{"request":"keys"}` + "\n",
		`{"request":"Status"}` + "\n",
		`{"request":""}` + "\n",
		`{"request":"status","key":"x"}` + "\n",
		`{"request":"status"}{"request":"connect"}` + "\n",
		`{"request":"local"}` + "\n",
		`{"request":"settings"}` + "\n",
		`{"request":"connect","seen":3}` + "\n",
		`{"request":"status","seen":-1}` + "\n",
		`{"request":"status","seen":"3"}` + "\n",
		`not json` + "\n",
		`{"request":"status"}`,
		`{"request":"status","server":"` + strings.Repeat("a", MaxRequest) + `"}` + "\n",
	} {
		if reply := ask(t, f, line); reply.Error != "not allowed" || reply.OK || reply.Status != nil {
			t.Errorf("%.60q answered %+v", line, reply)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused request reached the service: %v", f.calls)
	}
}

func TestThePipeRefusesAnExitThatIsNotOffered(t *testing.T) {
	f := &fake{}
	for _, server := range []string{server2, server3, laptop1, "55555555-5555-4555-8555-555555555555", "server-1"} {
		if reply := ask(t, f, `{"request":"exit","server":"`+server+`"}`+"\n"); reply.Error != ErrNotOffered.Error() {
			t.Errorf("exit through %s answered %+v", server, reply)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused exit reached the service: %v", f.calls)
	}
	if reply := ask(t, f, `{"request":"exit","server":"`+server1+`"}`+"\n"); !reply.OK {
		t.Fatalf("an offered exit answered %+v", reply)
	}
	if reply := ask(t, f, `{"request":"exit","server":""}`+"\n"); !reply.OK {
		t.Fatalf("None answered %+v", reply)
	}
	if !slices.Equal(f.calls, []string{"exit " + server1, "exit "}) {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestThePipeRefusesAHeldExit(t *testing.T) {
	f := &fake{held: []string{server1}}
	if reply := ask(t, f, `{"request":"exit","server":"`+server1+`"}`+"\n"); reply.Error != ErrNotOffered.Error() {
		t.Fatalf("a held exit answered %+v", reply)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a held exit reached the service: %v", f.calls)
	}
}

func TestThePipeCarriesTheTraysRequests(t *testing.T) {
	f := &fake{}
	for _, line := range []string{
		`{"request":"connect"}`,
		`{"request":"disconnect"}`,
		`{"request":"local","on":true}`,
		`{"request":"local","on":false}`,
		`{"request":"settings","notifyOffline":true}`,
	} {
		if reply := ask(t, f, line+"\n"); !reply.OK || reply.Error != "" {
			t.Errorf("%s answered %+v", line, reply)
		}
	}
	if reply := ask(t, f, `{"request":"update"}`+"\n"); reply.OK || reply.Error != "Updating the agent is not available yet." {
		t.Errorf("update answered %+v", reply)
	}
	reply := ask(t, f, `{"request":"status"}`+"\n")
	if !reply.OK || reply.Status == nil || reply.Status.Name != "laptop-1" || !reply.Status.Connected {
		t.Fatalf("status answered %+v", reply)
	}
	if reply := ask(t, f, `{"request":"status","seen":7}`+"\n"); !reply.OK || reply.Status == nil {
		t.Fatalf("status with the last note seen answered %+v", reply)
	}
	if want := []string{"connect", "disconnect", "local on", "local off", "settings", "update", "status", "status"}; !slices.Equal(f.calls, want) {
		t.Fatalf("calls %v, want %v", f.calls, want)
	}
	if !slices.Equal(f.seen, []uint64{0, 7}) {
		t.Fatalf("seen %v", f.seen)
	}
}

type clock struct{ now time.Time }

type slow struct {
	fake
	clock *clock
}

func (s *slow) Connect(on bool) error {
	s.clock.now = s.clock.now.Add(6 * time.Second)
	return s.fake.Connect(on)
}

type timedConn struct {
	clock *clock
	in    *strings.Reader
	out   bytes.Buffer
	read  time.Time
	write time.Time
}

func (c *timedConn) Read(buffer []byte) (int, error) {
	if !c.clock.now.Before(c.read) {
		return 0, errors.New("read deadline")
	}
	return c.in.Read(buffer)
}

func (c *timedConn) Write(buffer []byte) (int, error) {
	if !c.clock.now.Before(c.write) {
		return 0, errors.New("write deadline")
	}
	return c.out.Write(buffer)
}

func (c *timedConn) SetReadDeadline(at time.Time) error {
	c.read = at
	return nil
}

func (c *timedConn) SetWriteDeadline(at time.Time) error {
	c.write = at
	return nil
}

func TestASlowChangeStillGetsItsReply(t *testing.T) {
	now := &clock{now: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}
	conn := &timedConn{clock: now, in: strings.NewReader(`{"request":"connect"}` + "\n")}
	if err := Converse(conn, &slow{clock: now}, func() time.Time { return now.now }); err != nil {
		t.Fatal(err)
	}
	if conn.out.String() != `{"ok":true}`+"\n" {
		t.Fatalf("reply %q", conn.out.String())
	}
}
