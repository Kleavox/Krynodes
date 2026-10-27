package tailscale

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
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
	report := Status(context.Background(), answer(`{"BackendState":"Running","AuthURL":"","Self":{"HostName":"vps-2","DNSName":"vps-2.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.12","fd7a:115c:a1e0::1"],"KeyExpiry":"2027-04-24T10:11:12+02:00"}}`, nil))
	if report.State != "running" || !slices.Equal(report.Addresses, []string{"100.101.7.12", "fd7a:115c:a1e0::1"}) || *report.Name != "vps-2.tail4d2a.ts.net" || *report.KeyExpiry != "2027-04-24T08:11:12Z" {
		t.Fatalf("got %+v", report)
	}
}

func TestAKeyThatNeverExpiresSaysSo(t *testing.T) {
	report := Status(context.Background(), answer(`{"BackendState":"Running","Self":{"DNSName":"pivox.tail4d2a.ts.net.","TailscaleIPs":["100.64.0.9"]}}`, nil))
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
