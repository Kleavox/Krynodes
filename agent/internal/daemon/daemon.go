package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	maxMessage = 2048
	maxLine    = 512
	maxRefused = 256
	maxOutput  = 128 << 10
)

var commandID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

var errStopped = errors.New("the agent stopped before this finished")

type Handler func(ctx context.Context, cmd trust.Command, progress func(string)) (message string, err error)

type Daemon struct {
	State     string
	Trust     func() trust.Trust
	SaveTrust func(trust.Trust) error
	Send      func(any) error
	Now       func() time.Time
	Handlers  map[string]Handler
	Resume    func(ctx context.Context, cmd trust.Command) (string, error)

	mu      sync.Mutex
	trustMu sync.Mutex
	waiters map[string]chan struct{}
	refused []named
}

func (d *Daemon) Handle(ctx context.Context, msg reporter.Command) {
	if !commandID.MatchString(msg.ID) {
		d.refuse(msg, errors.New("the command id is not valid"))
		return
	}
	digest := digestOf(msg)
	d.mu.Lock()
	stored, found, err := d.read(msg.ID)
	if err != nil {
		d.mu.Unlock()
		d.refuse(msg, fmt.Errorf("the ledger cannot be read: %w", err))
		return
	}
	if found {
		d.mu.Unlock()
		switch {
		case stored.Digest != digest:
			d.refuse(msg, errors.New("this command id was already used"))
		case stored.Result != nil:
			d.send(stored.Kind, *stored.Result)
		}
		return
	}
	cmd, refusal := d.verify(msg)
	if refusal != nil {
		d.mu.Unlock()
		d.refuse(msg, refusal)
		return
	}
	record := entry{Digest: digest, Kind: msg.Kind, Command: &cmd, At: d.Now()}
	record.ExpiresAt, _ = time.Parse(time.RFC3339Nano, cmd.ExpiresAt)
	if err := d.write(msg.ID, record); err != nil {
		d.mu.Unlock()
		d.refuse(msg, fmt.Errorf("the ledger cannot be written: %w", err))
		return
	}
	d.mu.Unlock()
	progress := func(line string) {
		_ = d.Send(reporter.Progress{Type: "progress", ID: msg.ID, Line: clip(line, maxLine)})
	}
	ctx, output := WithOutput(ctx)
	message, err := d.Handlers[msg.Kind+"/"+msg.Action](ctx, cmd, progress)
	if ctx.Err() != nil {
		return
	}
	result := outcome(msg.ID, message, err)
	result.Output = output()
	d.finish(msg.ID, result)
}

type outputKey struct{}

func WithOutput(ctx context.Context) (context.Context, func() string) {
	var output string
	return context.WithValue(ctx, outputKey{}, &output), func() string { return output }
}

func Output(ctx context.Context, text string) {
	if slot, ok := ctx.Value(outputKey{}).(*string); ok {
		*slot = clip(text, maxOutput)
	}
}

func (d *Daemon) verify(msg reporter.Command) (trust.Command, error) {
	key := msg.Kind + "/" + msg.Action
	if d.Handlers[key] == nil {
		return trust.Command{}, fmt.Errorf("this server cannot run %s", key)
	}
	if msg.Kind == "trust" {
		current := d.Trust()
		if _, err := trust.ApplyTrustChange(current, []byte(msg.Signed), d.Now()); err != nil {
			return trust.Command{}, err
		}
		return trust.Command{V: 1, ID: msg.ID, NodeID: current.NodeID, Kind: msg.Kind, Name: msg.Name, Action: msg.Action, Args: map[string]string{"change": msg.Signed}}, nil
	}
	return trust.VerifyCommand(d.Trust(), msg, d.Now())
}

func (d *Daemon) Ack(id string) {
	if !commandID.MatchString(id) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if stored, found, err := d.read(id); err == nil && found && stored.Result != nil && !stored.Acked {
		stored.Acked, stored.Result.Output = true, ""
		if err := d.write(id, stored); err != nil {
			log.Printf("record the ack for %s: %v", id, err)
		}
	}
	d.refused = slices.DeleteFunc(d.refused, func(item named) bool { return item.id == id })
	if waiter, ok := d.waiters[id]; ok {
		close(waiter)
		delete(d.waiters, id)
	}
}

func (d *Daemon) afterAck(id string, limit time.Duration, act func()) {
	waiter := make(chan struct{})
	d.mu.Lock()
	if d.waiters == nil {
		d.waiters = map[string]chan struct{}{}
	}
	d.waiters[id] = waiter
	d.mu.Unlock()
	go func() {
		timer := time.NewTimer(limit)
		defer timer.Stop()
		select {
		case <-waiter:
		case <-timer.C:
		}
		act()
	}()
}

func (d *Daemon) finish(id string, result *reporter.Result) {
	d.mu.Lock()
	stored, found, err := d.read(id)
	if err == nil && found {
		stored.Result, stored.At = result, d.Now()
		err = d.write(id, stored)
	}
	d.mu.Unlock()
	if err != nil {
		log.Printf("record the result of %s: %v", id, err)
	}
	d.send(stored.Kind, *result)
}

func (d *Daemon) refuse(msg reporter.Command, err error) {
	result := outcome(msg.ID, "", err)
	d.mu.Lock()
	d.refused = append(d.refused, named{msg.ID, entry{Kind: msg.Kind, Result: result, At: d.Now()}})
	if len(d.refused) > maxRefused {
		d.refused = slices.Delete(d.refused, 0, len(d.refused)-maxRefused)
	}
	d.mu.Unlock()
	d.send(msg.Kind, *result)
}

func (d *Daemon) send(kind string, result reporter.Result) {
	if kind == "trust" {
		if current := d.Trust(); len(current.Core) > 0 {
			report := current.Report()
			result.Trust = &report
		}
	}
	_ = d.Send(result)
}

func outcome(id, message string, err error) *reporter.Result {
	if err != nil {
		message = err.Error()
	}
	return &reporter.Result{Type: "result", ID: id, OK: err == nil, Message: clip(message, maxMessage)}
}

func digestOf(msg reporter.Command) string {
	encoded, _ := json.Marshal([]string{msg.Kind, msg.Name, msg.Action, msg.Signed})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func clip(text string, most int) string {
	if len(text) <= most {
		return text
	}
	cut := most
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
