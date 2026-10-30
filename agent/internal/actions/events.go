package actions

import (
	"slices"
	"time"
	"unicode/utf16"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	eventsFile   = "events.json"
	eventsKept   = 24 * time.Hour
	eventsMax    = 50
	eventIDMax   = 64
	eventTextMax = 500
)

type eventLog struct {
	Events []reporter.Event `json:"events"`
}

func clipText(text string, most int) string {
	used := 0
	for at, r := range text {
		if used += utf16.RuneLen(r); used > most {
			return text[:at]
		}
	}
	return text
}

func (e Executor) event(kind, id string, detail map[string]string) {
	if len(id) > eventIDMax {
		id = kind + ":" + shortHash(id)
	}
	for key, value := range detail {
		detail[key] = clipText(value, eventTextMax)
	}
	log, _ := readState[eventLog](e.StateDir, eventsFile)
	if slices.ContainsFunc(log.Events, func(event reporter.Event) bool { return event.ID == id }) {
		return
	}
	now := e.Now().UTC()
	log.Events = slices.DeleteFunc(log.Events, func(event reporter.Event) bool {
		at, err := time.Parse(time.RFC3339, event.At)
		return err != nil || now.Sub(at) > eventsKept
	})
	log.Events = append(log.Events, reporter.Event{ID: id, Kind: kind, At: now.Format(time.RFC3339), Detail: detail})
	if len(log.Events) > eventsMax {
		log.Events = log.Events[len(log.Events)-eventsMax:]
	}
	writeJSON(e.StateDir, eventsFile, log, 0o640)
}
