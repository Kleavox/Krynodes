package actions

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestAnEventAlwaysFitsWhatTheDashboardTakes(t *testing.T) {
	executor, _ := securityExecutor(t)
	id := "stack:" + strings.Repeat("a", 70) + ":497410"
	for range 2 {
		executor.event("stack", id, map[string]string{"stack": "panel", "tried": strings.Repeat("é😀", 400)})
	}
	events := readEvents(t, executor)
	if len(events) != 1 {
		t.Fatalf("events %+v", events)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`).MatchString(events[0].ID) {
		t.Fatalf("id %q", events[0].ID)
	}
	if tried := events[0].Detail["tried"]; len(utf16.Encode([]rune(tried))) > 500 || !strings.HasPrefix(tried, "é😀") || events[0].Detail["stack"] != "panel" {
		t.Fatalf("detail %q", events[0].Detail)
	}
}

func TestAnEventIDWithOtherCharactersIsHashed(t *testing.T) {
	executor, _ := securityExecutor(t)
	executor.event("wrong-port", "wrong-port:10.88.0.3:10.88.0.2:5432/tcp:497410", map[string]string{"from": "10.88.0.3"})
	events := readEvents(t, executor)
	if len(events) != 1 || !regexp.MustCompile(`^wrong-port:[A-Za-z0-9_.:-]{1,53}$`).MatchString(events[0].ID) {
		t.Fatalf("events %+v", events)
	}
}
