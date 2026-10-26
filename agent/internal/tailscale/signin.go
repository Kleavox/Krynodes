package tailscale

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

type Stream func(ctx context.Context, each func(string), name string, args ...string) error

type Login struct {
	URL     string
	Running bool
}

const signInTimeout = 45 * time.Second

func up(ctx context.Context, stream Stream, args []string) (string, []string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, signInTimeout)
	defer cancel()
	link, failure := "", ""
	var suggested []string
	err := stream(ctx, func(line string) {
		trimmed := strings.TrimSpace(line)
		switch {
		case link != "":
		case strings.HasPrefix(trimmed, "https://") && !strings.ContainsAny(trimmed, " \t"):
			link = trimmed
			cancel()
		case strings.HasPrefix(trimmed, "tailscale up "):
			suggested = strings.Fields(trimmed)[1:]
		case trimmed != "":
			failure = trimmed
		}
	}, Binary, args...)
	return link, suggested, failure, err
}

func SignIn(ctx context.Context, run Runner, stream Stream) (Login, error) {
	before := Status(ctx, run)
	if before.State == "stopped" {
		return Login{}, errors.New("tailscaled is not running; start it from Services, then sign in")
	}
	args := []string{"up", "--accept-dns=false", "--ssh=false", "--timeout=30s"}
	if before.State == "running" {
		args = []string{"up", "--force-reauth", "--timeout=30s"}
	}
	link, suggested, failure, err := up(ctx, stream, args)
	if link == "" && len(suggested) > 0 && slices.ContainsFunc(suggested[1:], func(flag string) bool { return !strings.HasPrefix(flag, "--") }) {
		suggested = nil
	}
	if link == "" && len(suggested) > 1 && suggested[0] == "up" {
		if before.State == "running" && !slices.Contains(suggested, "--force-reauth") {
			suggested = append(suggested, "--force-reauth")
		}
		link, _, failure, err = up(ctx, stream, append(suggested, "--timeout=30s"))
	}
	if link != "" {
		return Login{URL: link}, nil
	}
	after, readErr := read(ctx, run)
	switch {
	case readErr == nil && after.AuthURL != "":
		return Login{URL: after.AuthURL}, nil
	case err == nil && Status(ctx, run).State == "running":
		return Login{Running: true}, nil
	case failure != "":
		return Login{}, errors.New(failure)
	case err != nil:
		return Login{}, err
	}
	return Login{}, errors.New("tailscaled gave no sign-in link")
}
