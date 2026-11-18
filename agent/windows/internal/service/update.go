package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/update"
)

const (
	releaseFile = "krynodes-windows-amd64.exe"
	stagedName  = "krynodes.new.exe"
	oldName     = "krynodes.old.exe"
	updateNote  = "update-note.txt"
	settle      = 20 * time.Second
)

var (
	ErrUpToDate   = errors.New("this agent is the newest release")
	latestPattern = regexp.MustCompile(`/releases/tag/agent-v(\d+\.\d+\.\d+)$`)
	rename        = os.Rename
)

type Release struct {
	Current    string
	Key        ed25519.PublicKey
	Executable string
	Latest     func(ctx context.Context) (string, error)
	Fetch      func(ctx context.Context, url string) ([]byte, error)
	Run        func(path string) (string, error)
	Write      func(path string, data []byte) error
}

func LatestFrom(location string) (string, bool) {
	match := latestPattern.FindStringSubmatch(location)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func ReleaseURL(version, name string) string {
	return fmt.Sprintf("%s/agent-v%s/%s", strings.TrimRight(update.DefaultBase, "/"), version, name)
}

func (r Release) Update(ctx context.Context) (string, error) {
	latest, err := r.Latest(ctx)
	if err != nil {
		return "", err
	}
	newer, err := update.IsNewer(latest, r.Current)
	if err != nil {
		return "", err
	}
	if !newer {
		return "", ErrUpToDate
	}
	url := ReleaseURL(latest, releaseFile)
	binary, err := r.Fetch(ctx, url)
	if err != nil {
		return "", err
	}
	checksum, err := r.Fetch(ctx, url+".sha256")
	if err != nil {
		return "", err
	}
	signature, err := r.Fetch(ctx, url+".sig")
	if err != nil {
		return "", fmt.Errorf("%s has no release signature: %w", latest, err)
	}
	if err := update.Verify(binary, checksum, signature, r.Key); err != nil {
		return "", fmt.Errorf("refusing %s: %w", latest, err)
	}
	return latest, swapIn(r.Write, r.Executable, binary, func(staged string) error {
		reported, err := r.Run(staged)
		if err != nil || strings.TrimSpace(reported) != latest {
			if err == nil {
				err = fmt.Errorf("it reports %q", strings.TrimSpace(reported))
			}
			return fmt.Errorf("the new agent does not run here: %v", err)
		}
		return nil
	})
}

func swapIn(write func(path string, data []byte) error, executable string, binary []byte, check func(staged string) error) error {
	dir := filepath.Dir(executable)
	staged := filepath.Join(dir, stagedName)
	if err := write(staged, binary); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("stage the new agent: %w", err)
	}
	if check != nil {
		if err := check(staged); err != nil {
			_ = os.Remove(staged)
			return err
		}
	}
	old := filepath.Join(dir, oldName)
	aside := false
	if _, err := os.Stat(executable); err == nil {
		if err := clearOld(old); err != nil {
			_ = os.Remove(staged)
			return fmt.Errorf("clear the previous agent: %w", err)
		}
		if err := rename(executable, old); err != nil {
			_ = os.Remove(staged)
			return fmt.Errorf("keep the running agent: %w", err)
		}
		aside = true
	}
	if err := rename(staged, executable); err != nil {
		if !aside {
			return fmt.Errorf("put the new agent in place: %w", err)
		}
		if back := rename(old, executable); back != nil {
			return fmt.Errorf("put the new agent in place: %v; putting the previous agent back also failed: %v; it is %s", err, back, old)
		}
		return fmt.Errorf("put the new agent in place: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		directory.Close()
	}
	return nil
}

func clearOld(old string) error {
	err := os.Remove(old)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	return rename(old, strings.TrimSuffix(old, ".exe")+"."+hex.EncodeToString(suffix)+".exe")
}

type Watch struct {
	Executable string
	Previous   string
	Stop       func() error
	Start      func() error
	PID        func() (uint32, error)
	Sleep      func(time.Duration)
	Note       func(line string)
}

func (w Watch) Run(next string) error {
	if w.stayedUp() {
		return nil
	}
	_ = w.Stop()
	dir := filepath.Dir(w.Executable)
	staged := filepath.Join(dir, stagedName)
	failed := fmt.Errorf("Krynodes %s did not stay up, so %s is back.", next, w.Previous)
	if err := rename(w.Executable, staged); err != nil {
		failed = fmt.Errorf("Krynodes %s did not stay up and could not be set aside: %v", next, err)
	} else if err := rename(filepath.Join(dir, oldName), w.Executable); err != nil {
		_ = rename(staged, w.Executable)
		failed = fmt.Errorf("Krynodes %s did not stay up and %s could not be put back: %v", next, w.Previous, err)
	}
	w.Note(failed.Error())
	if err := w.Start(); err != nil {
		return fmt.Errorf("%v It did not start: %v", failed, err)
	}
	return failed
}

func (w Watch) stayedUp() bool {
	if w.Stop() != nil || w.Start() != nil {
		return false
	}
	w.Sleep(settle)
	first, err := w.PID()
	if err != nil || first == 0 {
		return false
	}
	w.Sleep(5 * time.Second)
	second, err := w.PID()
	return err == nil && second == first
}

func (s *Service) Offer(latest, current string) {
	newer, err := update.IsNewer(latest, current)
	if err != nil || !newer {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read()
	if err != nil || record.Offered == latest {
		return
	}
	record.Offered = latest
	if err := s.save(record); err != nil {
		log.Printf("remember the offered update: %v", err)
		return
	}
	s.say("Krynodes " + latest + " is available. Settings, Update Agent installs it.")
}

func Tidy(executable string) {
	dir := filepath.Dir(executable)
	found, _ := filepath.Glob(filepath.Join(dir, "krynodes.old*.exe"))
	for _, path := range append(found, filepath.Join(dir, stagedName)) {
		_ = os.RemoveAll(path)
	}
}
