//go:build linux

package stacks

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGuardWaitsForAnotherPassOfItsOwn(t *testing.T) {
	ipv6(t, true)
	useResolvers(t, "", "")
	useLock(t)

	unlock, err := lockGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := newTables()
	done := make(chan error, 1)
	go func() { done <- Guard(context.Background(), s.run) }()
	select {
	case err := <-done:
		t.Fatalf("a pass ran while another held the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil || len(s.changes()) == 0 {
			t.Fatalf("the pass runs once the lock is free: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pass never ran after the lock was free")
	}

	unlock, _ = lockGuard(context.Background())
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	other := newTables()
	if err := Guard(ctx, other.run); err == nil || !strings.Contains(err.Error(), "another pass of the guard") || len(other.calls) > 0 {
		t.Fatalf("a pass that cannot get the lock in time says so and touches nothing: %v %q", err, other.calls)
	}
}

func TestUnguardWaitsForAPassOfTheGuard(t *testing.T) {
	useLock(t)

	unlock, err := lockGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := newTables()
	s.seed("iptables", "DOCKER-USER", establishedReturn, sameBridgeReturn)
	done := make(chan struct{})
	go func() {
		Unguard(context.Background(), s.run)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Unguard ran while a pass of the guard held the lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
		if rules := s.rules("iptables", "DOCKER-USER"); len(rules) != 0 {
			t.Fatalf("Unguard takes the RETURNs away once the lock is free: %q", rules)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Unguard never ran after the lock was free")
	}
}
