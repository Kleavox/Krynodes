package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/network"
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
	if err := writeJSON(e.StateDir, releaseFile, pending, 0o640); err != nil {
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
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		return e.failed(request, err, "")
	}
	cfg.Token = string(token)
	if err := config.Save(e.ConfigPath, cfg); err != nil {
		return e.failed(request, err, "")
	}
	keys := filepath.Join(e.StateDir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		return e.failed(request, err, "")
	}
	if err := os.Rename(filepath.Join(dir, "seal.key"), filepath.Join(keys, "seal.key")); err != nil {
		return e.failed(request, err, "")
	}
	if record := e.readNetwork(); record.Key != "" {
		for _, name := range []string{"key", "signer"} {
			if err := os.Rename(filepath.Join(dir, name), filepath.Join(e.networkDir(), name)); err != nil {
				return e.failed(request, err, "")
			}
		}
		record.Key, record.Signer, record.Announce = pending.Key, pending.Signer, nil
		if err := e.saveNetwork(record); err != nil {
			return e.failed(request, err, "")
		}
	}
	os.Remove(filepath.Join(e.StateDir, releaseFile))
	os.RemoveAll(dir)
	e.retake(ctx, true)
	e.Run(context.WithoutCancel(ctx), "systemctl", "restart", "--no-block", agentUnit)
	return Result{ID: request.ID, OK: true, Output: "released: new keys and a new sign-in to Krynodes", FinishedAt: e.stamp()}
}
