package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/update"
)

const (
	releaseFile = "krynodes-windows-amd64.exe"
	stagedName  = "krynodes.new.exe"
	oldName     = "krynodes.old.exe"
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

func Tidy(executable string) {
	dir := filepath.Dir(executable)
	found, _ := filepath.Glob(filepath.Join(dir, "krynodes.old*.exe"))
	for _, path := range append(found, filepath.Join(dir, stagedName)) {
		_ = os.RemoveAll(path)
	}
}
