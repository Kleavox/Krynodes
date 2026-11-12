package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const (
	agentUnit   = "krynodes.service"
	releaseDir  = "release"
	releaseFor  = 10 * time.Minute
	releaseTime = "2006-01-02T15:04:05.000Z"
)

func releaseCode(pending reporter.Release) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{pending.Key, pending.Signer, pending.Seal, pending.Token, pending.Expires}, "\n")))
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])[:10]
	return code[:5] + "-" + code[5:]
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (e Executor) ReleaseCode(mark string) (string, error) {
	_, locked := os.Stat(filepath.Join(e.StateDir, "lockdown.json"))
	_, marked := os.Stat(mark)
	if locked != nil && marked != nil {
		return "", errors.New("this server is not cut off; a release code is made only on a quarantined or locked down server")
	}
	dir := filepath.Join(e.StateDir, releaseDir)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	keys, err := network.Load(dir, true)
	if err != nil {
		return "", err
	}
	key, err := seal.Load(dir)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := writeWhole(dir, "token", []byte(token), 0o600); err != nil {
		return "", err
	}
	pending := reporter.Release{Key: keys.Public, Signer: keys.Signer, Seal: seal.Public(key), Token: tokenHash(token), Expires: e.Now().UTC().Add(releaseFor).Format(releaseTime)}
	if err := writeJSON(e.StateDir, releaseFile, pending, 0o644); err != nil {
		return "", err
	}
	return releaseCode(pending), nil
}

func (e Executor) release(ctx context.Context, request Request, command Command) Result {
	var pending reporter.Release
	if err := readJSON(filepath.Join(e.StateDir, releaseFile), &pending); err != nil {
		return e.refuse(request.ID, errors.New("no release code was made on this server; run sudo kry release-code there"))
	}
	ends, err := time.Parse(time.RFC3339, pending.Expires)
	if err != nil || !e.Now().Before(ends) {
		return e.refuse(request.ID, errors.New("the release code has ended; run sudo kry release-code again"))
	}
	args := command.Args
	if len(args) != 5 || args["key"] != pending.Key || args["signer"] != pending.Signer || args["seal"] != pending.Seal || args["token"] != pending.Token || args["code"] != releaseCode(pending) {
		return e.refuse(request.ID, errors.New("the code does not match the keys this server made"))
	}
	dir := filepath.Join(e.StateDir, releaseDir)
	token, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil || tokenHash(string(token)) != pending.Token {
		return e.refuse(request.ID, errors.New("the keys this server made are gone; run sudo kry release-code again"))
	}
	enforced, err := e.enforceAgain(ctx)
	if err != nil {
		return e.refuse(request.ID, fmt.Errorf("SELinux could not be set back to enforcing, so nothing was released: %w", err))
	}
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		return e.failed(request, err, "")
	}
	cfg.Token = string(token)
	keys := filepath.Join(e.StateDir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		return e.failed(request, err, "")
	}
	record := e.readNetwork()
	moves := [][2]string{{filepath.Join(dir, "seal.key"), filepath.Join(keys, "seal.key")}}
	if record.Key != "" {
		for _, name := range []string{"key", "signer"} {
			moves = append(moves, [2]string{filepath.Join(dir, name), filepath.Join(e.networkDir(), name)})
		}
	}
	undo, err := swapFiles(moves)
	if err != nil {
		return e.failed(request, err, "")
	}
	if record.Key != "" {
		before := record
		record.Key, record.Signer, record.Announce = pending.Key, pending.Signer, nil
		if err := e.saveNetwork(record); err != nil {
			undo()
			return e.failed(request, err, "")
		}
		if err := config.Save(e.ConfigPath, cfg); err != nil {
			undo()
			e.saveNetwork(before)
			return e.failed(request, err, "")
		}
	} else if err := config.Save(e.ConfigPath, cfg); err != nil {
		undo()
		return e.failed(request, err, "")
	}
	for _, move := range moves {
		os.Remove(move[1] + ".before-release")
	}
	os.Remove(filepath.Join(e.StateDir, releaseFile))
	os.RemoveAll(dir)
	e.retake(ctx, true)
	e.Run(context.WithoutCancel(ctx), "systemctl", "restart", "--no-block", agentUnit)
	output := "released: new keys and a new sign-in to Krynodes"
	if enforced {
		output += "; SELinux enforces again"
	}
	return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
}

func (e Executor) enforceAgain(ctx context.Context) (bool, error) {
	env := e.recipeEnv()
	found := confine.Read(e.Root, string(recipes.Detect(env).Family))
	applied, managed := e.readRecipes().Applied["confinement"]
	if !managed || applied.Saved["system"] != found.System || found.System != confine.SELinux || found.Mode != confine.Permissive || restartDue(found, applied.Saved) {
		return false, nil
	}
	if err := e.markConfinement("release"); err != nil {
		return false, err
	}
	defer e.holdConfinement("release")()
	return true, recipes.EnforceSELinux(ctx, env)
}

func swapFiles(moves [][2]string) (func(), error) {
	done := 0
	undo := func() {
		for _, move := range slices.Backward(moves[:done]) {
			os.Rename(move[1], move[0])
			os.Rename(move[1]+".before-release", move[1])
		}
	}
	for _, move := range moves {
		kept := move[1] + ".before-release"
		if err := os.Rename(move[1], kept); err != nil && !errors.Is(err, os.ErrNotExist) {
			undo()
			return nil, err
		}
		if err := os.Rename(move[0], move[1]); err != nil {
			os.Rename(kept, move[1])
			undo()
			return nil, err
		}
		done++
	}
	return undo, nil
}
