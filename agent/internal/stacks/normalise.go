package stacks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/docker"
)

const (
	maxNormalisedBytes = 64 << 10
	maxComposeError    = 300
	normaliseID        = 2147418112
	normalisedFile     = "out.json"
	searchPath         = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

var (
	chown         = os.Chown
	inlineComment = regexp.MustCompile(`\s#.*$`)
)

func Normalise(ctx context.Context, run docker.Runner, name string, compose, env []byte) (map[string]any, error) {
	dir, err := os.MkdirTemp("", "kry-compose-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	files := map[string][]byte{composeFile: compose}
	if env != nil {
		files[envFile] = env
	}
	for file, body := range files {
		path := filepath.Join(dir, file)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return nil, err
		}
		if err := chown(path, normaliseID, normaliseID); err != nil {
			return nil, err
		}
	}
	if err := chown(dir, normaliseID, normaliseID); err != nil {
		return nil, err
	}
	id := strconv.Itoa(normaliseID)
	output, _, err := run(ctx, "setpriv", "--reuid="+id, "--regid="+id, "--clear-groups",
		"env", "-i", searchPath, "HOME="+dir,
		"docker", "compose", "--project-name", name, "--project-directory", dir, "-f", filepath.Join(dir, composeFile),
		"config", "--format", "json", "--no-env-resolution", "-o", filepath.Join(dir, normalisedFile))
	if err != nil {
		return nil, fmt.Errorf("compose could not read the file: %s", clip(redact(strings.ReplaceAll(string(output), dir, "."), env), maxComposeError))
	}
	return readNormalised(filepath.Join(dir, normalisedFile))
}

func redact(text string, env []byte) string {
	var secrets []string
	for line := range strings.SplitSeq(string(env), "\n") {
		line = strings.TrimSpace(line)
		candidates := []string{line}
		if _, value, found := strings.Cut(line, "="); found {
			value = strings.TrimSpace(value)
			candidates = append(candidates, value, strings.Trim(value, `"'`), parsedValue(value))
		}
		for _, one := range candidates {
			if utf8.RuneCountInString(one) >= 3 {
				secrets = append(secrets, one)
			}
		}
	}
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	for _, secret := range secrets {
		text = strings.ReplaceAll(text, secret, "…")
	}
	return text
}

func parsedValue(value string) string {
	if value != "" && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[1 : end+1]
		}
		return value[1:]
	}
	return strings.TrimSpace(inlineComment.ReplaceAllString(value, ""))
}

func NormaliseFull(ctx context.Context, run docker.Runner, name, home, folder string) (map[string]any, error) {
	dir, err := os.MkdirTemp("", "kry-compose-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	args := append([]string{"-i", searchPath}, composeCommand(name, home, folder, filepath.Join(folder, composeFile))...)
	args = append(args, "config", "--format", "json", "--no-env-resolution", "-o", filepath.Join(dir, normalisedFile))
	output, _, err := run(ctx, "env", args...)
	if err != nil {
		env, _ := readEnv(folder)
		return nil, fmt.Errorf("compose could not read the file: %s", clip(redact(strings.ReplaceAll(string(output), dir, "."), env), maxComposeError))
	}
	return readNormalised(filepath.Join(dir, normalisedFile))
}

func ClearTemp(dir string) {
	stale, _ := filepath.Glob(filepath.Join(dir, "kry-compose-*"))
	for _, path := range stale {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			log.Printf("remove %s: %v", path, err)
		}
	}
}

func composeCommand(name, home, folder, file string) []string {
	args := []string{"docker", "compose", "--project-name", name, "--project-directory", home, "-f", file}
	if info, err := os.Lstat(filepath.Join(folder, envFile)); err == nil && info.Mode().IsRegular() {
		args = append(args, "--env-file", filepath.Join(folder, envFile))
	}
	return args
}

func readNormalised(path string) (map[string]any, error) {
	file, err := openNoFollow(path)
	if err != nil {
		return nil, errors.New("compose did not return a readable file")
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("compose did not return a readable file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxNormalisedBytes+1))
	if err != nil {
		return nil, errors.New("compose did not return a readable file")
	}
	if len(raw) > maxNormalisedBytes {
		return nil, errors.New("compose returned more than 64 KB")
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil || config == nil {
		return nil, errors.New("compose did not return a readable file")
	}
	return config, nil
}

func clip(text string, most int) string {
	text = strings.TrimSpace(text)
	if len(text) <= most {
		return text
	}
	text = text[:most]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text
}
