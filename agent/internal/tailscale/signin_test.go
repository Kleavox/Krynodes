package tailscale

import (
	"context"
	"slices"
	"strings"
	"testing"
)

type tailscaled struct {
	state    string
	authURL  string
	ran      [][]string
	answers  map[string][]string
	held     bool
	canceled bool
}

func (d *tailscaled) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	if d.state == "" {
		return nil, 1, context.DeadlineExceeded
	}
	return []byte(`{"BackendState":"` + d.state + `","AuthURL":"` + d.authURL + `","Self":{"DNSName":"vps-2.tail0000.ts.net.","TailscaleIPs":["100.101.7.12"]}}`), 0, nil
}

func (d *tailscaled) stream(ctx context.Context, each func(string), name string, args ...string) error {
	d.ran = append(d.ran, append([]string{name}, args...))
	for _, line := range d.answers[strings.Join(args, " ")] {
		each(line)
	}
	if d.held {
		<-ctx.Done()
		d.canceled = true
		return ctx.Err()
	}
	return nil
}

const visit = "\thttps://login.tailscale.com/a/1a2b3c4d5e6f"

func TestAFirstSignInKeepsDNSAndSSHOffAndReturnsTheLinkAtOnce(t *testing.T) {
	d := &tailscaled{state: "NeedsLogin", held: true, answers: map[string][]string{
		"up --accept-dns=false --ssh=false --timeout=30s": {"", "To authenticate, visit:", "", visit, ""},
	}}
	login, err := SignIn(context.Background(), d.run, d.stream)
	if err != nil || login.URL != strings.TrimSpace(visit) || login.Running {
		t.Fatalf("got %+v %v", login, err)
	}
	if !d.canceled || len(d.ran) != 1 || d.ran[0][0] != Binary {
		t.Fatalf("ran %v, canceled %v", d.ran, d.canceled)
	}
}

func TestSigningInAgainKeepsTheOtherSettings(t *testing.T) {
	d := &tailscaled{state: "Running", held: true, answers: map[string][]string{
		"up --force-reauth --timeout=30s": {
			"Error: changing settings via 'tailscale up' requires mentioning all non-default flags. To proceed, either re-run your command with --reset or use the command below to explicitly mention the current value of all non-default settings:",
			"",
			"\ttailscale up --accept-routes --advertise-tags=tag:server --force-reauth",
		},
		"up --accept-routes --advertise-tags=tag:server --force-reauth --timeout=30s": {"To authenticate, visit:", visit},
	}}
	d.held = false
	login, err := SignIn(context.Background(), d.run, func(ctx context.Context, each func(string), name string, args ...string) error {
		d.held = len(d.ran) == 1
		return d.stream(ctx, each, name, args...)
	})
	if err != nil || login.URL != strings.TrimSpace(visit) {
		t.Fatalf("got %+v %v after %v", login, err, d.ran)
	}
	if len(d.ran) != 2 || !slices.Equal(d.ran[1][1:], []string{"up", "--accept-routes", "--advertise-tags=tag:server", "--force-reauth", "--timeout=30s"}) {
		t.Fatalf("ran %v", d.ran)
	}
}

func TestASignInThatNeedsNoLinkSaysSo(t *testing.T) {
	d := &tailscaled{state: "Running"}
	login, err := SignIn(context.Background(), d.run, d.stream)
	if err != nil || !login.Running || login.URL != "" {
		t.Fatalf("got %+v %v", login, err)
	}
	d.authURL, d.state = "https://login.tailscale.com/a/ffff", "NeedsLogin"
	login, err = SignIn(context.Background(), d.run, func(context.Context, func(string), string, ...string) error {
		return context.DeadlineExceeded
	})
	if err != nil || login.URL != "https://login.tailscale.com/a/ffff" {
		t.Fatalf("got %+v %v", login, err)
	}
}

func TestSigningInWaitsForTailscaled(t *testing.T) {
	d := &tailscaled{}
	if _, err := SignIn(context.Background(), d.run, d.stream); err == nil || !strings.Contains(err.Error(), "tailscaled is not running") || len(d.ran) != 0 {
		t.Fatalf("got %v after %v", err, d.ran)
	}
}
