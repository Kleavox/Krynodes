package tailscale

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func answer(output string, err error) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if command := strings.Join(append([]string{name}, args...), " "); command != "tailscale status --json" {
			return nil, -1, errors.New("unexpected " + command)
		}
		return []byte(output), 0, err
	}
}

func TestTailscaledSaysWhereTheServerIsOnTheTailnet(t *testing.T) {
	report := Status(context.Background(), answer(`{"BackendState":"Running","AuthURL":"","Self":{"HostName":"vps-2","DNSName":"vps-2.tail0000.ts.net.","TailscaleIPs":["100.101.7.12","fd7a:115c:a1e0::1"],"KeyExpiry":"2027-04-24T10:11:12+02:00"}}`, nil))
	if report.State != "running" || !slices.Equal(report.Addresses, []string{"100.101.7.12", "fd7a:115c:a1e0::1"}) || *report.Name != "vps-2.tail0000.ts.net" || *report.KeyExpiry != "2027-04-24T08:11:12Z" {
		t.Fatalf("got %+v", report)
	}
}

func TestAKeyThatNeverExpiresSaysSo(t *testing.T) {
	report := Status(context.Background(), answer(`{"BackendState":"Running","Self":{"DNSName":"server-1.tail0000.ts.net.","TailscaleIPs":["100.64.0.9"]}}`, nil))
	if report.State != "running" || report.KeyExpiry != nil {
		t.Fatalf("got %+v", report)
	}
}

func TestAServerNotSignedInSaysSo(t *testing.T) {
	for _, state := range []string{"NeedsLogin", "NeedsMachineAuth", "Stopped", "NoState"} {
		report := Status(context.Background(), answer(`{"BackendState":"`+state+`","AuthURL":"https://login.tailscale.com/a/1234","Self":{"DNSName":"","TailscaleIPs":null}}`, nil))
		if report.State != "needs-login" || report.Addresses == nil || len(report.Addresses) != 0 || report.Name != nil {
			t.Fatalf("%s: got %+v", state, report)
		}
	}
}

func TestTailscaledThatDoesNotAnswerIsStopped(t *testing.T) {
	report := Status(context.Background(), answer("failed to connect to local tailscaled; it doesn't appear to be running", errors.New("exit status 1")))
	if report.State != "stopped" || report.Addresses == nil || report.Name != nil || report.KeyExpiry != nil {
		t.Fatalf("got %+v", report)
	}
}

func answers(outputs map[string]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		output, ok := outputs[strings.Join(append([]string{name}, args...), " ")]
		if !ok {
			return nil, 1, errors.New("exit status 1")
		}
		return []byte(output), 0, nil
	}
}

func TestTheReportSaysWhetherTheServerIsAnExitNodeAndUsesTailscaleDNS(t *testing.T) {
	running := `{"BackendState":"Running","Self":{"DNSName":"server-1.tail0000.ts.net.","TailscaleIPs":["100.64.0.9"],"AllowedIPs":["100.64.0.9/32"%s]}}`
	for _, c := range []struct {
		allowed, prefs string
		exitNode       *reporter.ExitNode
		acceptDNS      *bool
	}{
		{"", `{"CorpDNS":false,"AdvertiseRoutes":null}`, &reporter.ExitNode{}, new(false)},
		{"", `{"CorpDNS":true,"AdvertiseRoutes":["0.0.0.0/0","::/0"]}`, &reporter.ExitNode{Advertised: true}, new(true)},
		{`,"0.0.0.0/0","::/0"`, `{"CorpDNS":false,"AdvertiseRoutes":["0.0.0.0/0","::/0"]}`, &reporter.ExitNode{Advertised: true, Approved: true}, new(false)},
	} {
		report := Status(context.Background(), answers(map[string]string{
			"tailscale status --json": fmt.Sprintf(running, c.allowed),
			"tailscale debug prefs":   c.prefs,
		}))
		if !reflect.DeepEqual(report.ExitNode, c.exitNode) || !reflect.DeepEqual(report.AcceptDNS, c.acceptDNS) {
			t.Fatalf("%s: got %+v %v", c.prefs, report.ExitNode, report.AcceptDNS)
		}
	}
}

func TestPrefsThatCannotBeReadAreNotGuessed(t *testing.T) {
	report := Status(context.Background(), answers(map[string]string{
		"tailscale status --json": `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.9"],"AllowedIPs":["0.0.0.0/0"]}}`,
	}))
	if report.State != "running" || report.ExitNode != nil || report.AcceptDNS != nil {
		t.Fatalf("got %+v", report)
	}
}

func TestSetChangesOnePreference(t *testing.T) {
	var ran []string
	run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		ran = append(ran, strings.Join(append([]string{name}, args...), " "))
		if args[1] == "--accept-dns=true" {
			return []byte("Error: cannot set accept-dns\n"), 1, errors.New("exit status 1")
		}
		return nil, 0, nil
	}
	if err := Set(context.Background(), run, "--advertise-exit-node=true"); err != nil {
		t.Fatal(err)
	}
	if err := Set(context.Background(), run, "--accept-dns=true"); err == nil || err.Error() != "Error: cannot set accept-dns" {
		t.Fatalf("got %v", err)
	}
	if !slices.Equal(ran, []string{"tailscale set --advertise-exit-node=true", "tailscale set --accept-dns=true"}) {
		t.Fatalf("ran %v", ran)
	}
}
