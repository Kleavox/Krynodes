package exit

import (
	"testing"
	"time"
)

var start = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func at(second int) time.Time {
	return start.Add(time.Duration(second) * time.Second)
}

func TestTheExitGoesAfterThirtySilentSeconds(t *testing.T) {
	var w ExitWatch
	if !w.Observe(at(0), true, false) {
		t.Fatal("an answering exit was dropped")
	}
	for second := 1; second < 30; second++ {
		if !w.Observe(at(second), false, false) {
			t.Fatalf("dropped after %d silent seconds", second)
		}
	}
	if w.Observe(at(30), false, false) {
		t.Fatal("kept after 30 silent seconds")
	}

	var fresh ExitWatch
	for second := 0; second < 30; second++ {
		if !fresh.Observe(at(second), false, false) {
			t.Fatalf("a new exit that never answered was dropped after %d s", second)
		}
	}
	if fresh.Observe(at(30), false, false) {
		t.Fatal("a new exit that never answered was kept for 30 s")
	}

	var back ExitWatch
	back.Observe(at(0), true, false)
	back.Observe(at(29), true, false)
	if !back.Observe(at(58), false, false) {
		t.Fatal("an answer did not restart the 30 seconds")
	}
}

func TestTheExitGoesAtOnceWhenHeld(t *testing.T) {
	var w ExitWatch
	w.Observe(at(0), true, false)
	if w.Observe(at(1), true, true) {
		t.Fatal("a held exit was kept")
	}
}

func TestASleepIsNotSilence(t *testing.T) {
	var w ExitWatch
	w.Observe(at(0), true, false)
	if !w.Observe(at(120), false, false) {
		t.Fatal("a resume after sleep dropped the exit")
	}
	for second := 121; second < 150; second++ {
		if !w.Observe(at(second), false, false) {
			t.Fatalf("dropped %d s after the resume", second-120)
		}
	}
	if w.Observe(at(150), false, false) {
		t.Fatal("kept after 30 silent seconds since the resume")
	}
}
