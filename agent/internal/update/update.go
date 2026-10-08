package update

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	RequestPath = "/var/lib/kry/update-request"
	StatusPath  = "/var/lib/kry/update-status"
	DefaultBase = "https://github.com/Kleavox/Krynodes/releases/download"
	maxDownload = 64 << 20
	maxSmall    = 64 << 10
	serviceUnit = "krynodes.service"
)

//go:embed release.pub
var releaseKey string

var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

var errNotFound = errors.New("HTTP 404")

type Options struct {
	RequestPath    string
	StatusPath     string
	BinaryPath     string
	Base           string
	Arch           string
	CurrentVersion string
	PublicKey      ed25519.PublicKey
	Client         *http.Client
	Run            func(name string, args ...string) error
	Output         func(name string, args ...string) (string, error)
	Stall          time.Duration
	Attempts       int
	Budget         time.Duration
	Settle         time.Duration
	Sleep          func(time.Duration)
}

type Status struct {
	Version string `json:"version"`
	Message string `json:"message"`
	At      string `json:"at"`
}

func PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(releaseKey))
	if err != nil {
		return nil, fmt.Errorf("decode release key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release key has %d bytes", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func WriteRequest(path, version, requestedAt string) (bool, error) {
	if !versionPattern.MatchString(version) {
		return false, fmt.Errorf("invalid version %q", version)
	}
	content := version + "\n" + requestedAt + "\n"
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return false, err
	}
	return true, os.Rename(temporary, path)
}

func ReadStatus(path, current string) (Status, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Status{}, false
	}
	var status Status
	if json.Unmarshal(raw, &status) != nil || status.Message == "" || !versionPattern.MatchString(status.Version) {
		return Status{}, false
	}
	newer, err := isNewer(status.Version, current)
	if err != nil || !newer {
		return Status{}, false
	}
	return status, true
}

func Apply(options Options) error {
	options = withDefaults(options)
	raw, err := os.ReadFile(options.RequestPath)
	if err != nil {
		return fmt.Errorf("read update request: %w", err)
	}
	target, _, _ := strings.Cut(string(raw), "\n")
	target = strings.TrimSpace(target)
	if !versionPattern.MatchString(target) {
		return fmt.Errorf("invalid version %q", target)
	}
	newer, err := isNewer(target, options.CurrentVersion)
	if err != nil {
		return err
	}
	if !newer {
		return fmt.Errorf("refusing %s: the running agent is %s", target, options.CurrentVersion)
	}
	if options.Arch != "amd64" && options.Arch != "arm64" {
		return fmt.Errorf("unsupported architecture %q", options.Arch)
	}
	if err := options.apply(target); err != nil {
		options.writeStatus(target, err.Error())
		return err
	}
	if options.StatusPath != "" {
		_ = os.Remove(options.StatusPath)
	}
	return nil
}

func withDefaults(options Options) Options {
	if options.Stall <= 0 {
		options.Stall = time.Minute
	}
	if options.Attempts <= 0 {
		options.Attempts = 5
	}
	if options.Budget <= 0 {
		options.Budget = 12 * time.Minute
	}
	if options.Settle <= 0 {
		options.Settle = 20 * time.Second
	}
	if options.Sleep == nil {
		options.Sleep = time.Sleep
	}
	return options
}

func (o Options) apply(target string) error {
	deadline := time.Now().Add(o.Budget)
	url := fmt.Sprintf("%s/agent-v%s/krynodes-linux-%s", strings.TrimRight(o.Base, "/"), target, o.Arch)
	o.clearDownloads(target)
	binary, err := o.binary(url, target, deadline)
	if err != nil {
		return err
	}
	checksum, err := o.small(url+".sha256", deadline)
	if err != nil {
		return err
	}
	signature, err := o.small(url+".sig", deadline)
	if err != nil {
		return err
	}
	if err := verify(binary, checksum, signature, o.PublicKey); err != nil {
		o.clearDownloads("")
		return err
	}
	if err := o.install(target, binary); err != nil {
		return err
	}
	o.clearDownloads("")
	return nil
}

func (o Options) download(target, kind string) string {
	return fmt.Sprintf("%s.%s-%s.download", o.BinaryPath, target, kind)
}

func (o Options) clearDownloads(keep string) {
	found, _ := filepath.Glob(o.BinaryPath + ".*.download")
	for _, path := range found {
		if keep == "" || !strings.HasPrefix(path, o.BinaryPath+"."+keep+"-") {
			_ = os.Remove(path)
		}
	}
}

func (o Options) binary(url, target string, deadline time.Time) ([]byte, error) {
	compressed := o.download(target, "gz")
	err := o.retry(deadline, false, func() error { return o.fetch(url+".gz", compressed) })
	if err == nil {
		data, err := gunzip(compressed)
		if err != nil {
			_ = os.Remove(compressed)
			return nil, fmt.Errorf("unpack %s.gz: %w", url, err)
		}
		return data, nil
	}
	if !errors.Is(err, errNotFound) {
		return nil, err
	}
	plain := o.download(target, "bin")
	if err := o.retry(deadline, true, func() error { return o.fetch(url, plain) }); err != nil {
		return nil, err
	}
	return os.ReadFile(plain)
}

func (o Options) small(url string, deadline time.Time) ([]byte, error) {
	var body []byte
	err := o.retry(deadline, true, func() error {
		var err error
		body, err = o.fetchSmall(url)
		return err
	})
	return body, err
}

func (o Options) retry(deadline time.Time, retryNotFound bool, attempt func() error) error {
	var last error
	for index := range o.Attempts {
		if index > 0 {
			if time.Now().After(deadline) {
				break
			}
			o.Sleep(min(5*time.Second<<(index-1), time.Minute))
		}
		last = attempt()
		if last == nil || (errors.Is(last, errNotFound) && !retryNotFound) {
			return last
		}
	}
	return last
}

type progress struct {
	reader io.Reader
	timer  *time.Timer
	stall  time.Duration
}

func (p *progress) Read(buffer []byte) (int, error) {
	count, err := p.reader.Read(buffer)
	if count > 0 {
		p.timer.Reset(p.stall)
	}
	return count, err
}

func (o Options) open(url string, offset int64) (*http.Response, context.CancelFunc, *time.Timer, error) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(o.Stall, cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		timer.Stop()
		cancel()
		return nil, nil, nil, err
	}
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := o.Client.Do(request)
	if err != nil {
		timer.Stop()
		cancel()
		if ctx.Err() != nil {
			return nil, nil, nil, fmt.Errorf("download %s: no answer for %s", url, o.Stall)
		}
		return nil, nil, nil, fmt.Errorf("download %s: %w", url, err)
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		timer.Stop()
		cancel()
		return nil, nil, nil, fmt.Errorf("download %s: %w", url, errNotFound)
	}
	return response, cancel, timer, nil
}

func (o Options) fetch(url, path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	have := info.Size()
	response, cancel, timer, err := o.open(url, have)
	if err != nil {
		return err
	}
	defer cancel()
	defer timer.Stop()
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		have = 0
		if err := file.Truncate(0); err != nil {
			return err
		}
	case http.StatusPartialContent:
	case http.StatusRequestedRangeNotSatisfiable:
		_ = file.Truncate(0)
		return fmt.Errorf("download %s: the saved part did not match, starting over", url)
	default:
		return fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	}
	if _, err := file.Seek(have, io.SeekStart); err != nil {
		return err
	}
	reader := &progress{reader: io.LimitReader(response.Body, maxDownload-have), timer: timer, stall: o.Stall}
	written, err := io.Copy(file, reader)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("download %s: no data for %s after %d bytes", url, o.Stall, have+written)
		}
		return fmt.Errorf("download %s: %w", url, err)
	}
	if response.ContentLength >= 0 && written < response.ContentLength {
		return fmt.Errorf("download %s: cut off after %d bytes", url, have+written)
	}
	return file.Close()
}

func (o Options) fetchSmall(url string) ([]byte, error) {
	response, cancel, timer, err := o.open(url, 0)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer timer.Stop()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(&progress{reader: io.LimitReader(response.Body, maxSmall), timer: timer, stall: o.Stall})
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	return body, nil
}

func gunzip(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownload {
		return nil, errors.New("the binary is larger than 64 MiB")
	}
	return data, nil
}

func verify(binary, checksum, signature []byte, key ed25519.PublicKey) error {
	fields := strings.Fields(string(checksum))
	sum := sha256.Sum256(binary)
	if len(fields) == 0 || !strings.EqualFold(fields[0], hex.EncodeToString(sum[:])) {
		return errors.New("checksum does not match the downloaded binary")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, binary, signature) {
		return errors.New("signature does not match the release key")
	}
	return nil
}

func (o Options) install(target string, binary []byte) error {
	current := o.BinaryPath
	staged := current + ".new"
	previous := current + ".previous"
	if err := writeSynced(staged, binary); err != nil {
		return fmt.Errorf("stage new binary: %w", err)
	}
	reported, err := o.Output(staged, "version")
	if err != nil || strings.TrimSpace(reported) != target {
		_ = os.Remove(staged)
		if err == nil {
			err = fmt.Errorf("it reports %q", strings.TrimSpace(reported))
		}
		return fmt.Errorf("the new binary does not run here: %v", err)
	}
	if err := os.Rename(current, previous); err != nil {
		return fmt.Errorf("keep previous binary: %w", err)
	}
	if err := os.Rename(staged, current); err != nil {
		_ = os.Rename(previous, current)
		return fmt.Errorf("install new binary: %w", err)
	}
	syncDirectory(filepath.Dir(current))
	failure := ""
	if err := o.Run(current, "install-service"); err != nil {
		failure = fmt.Sprintf("refresh service units: %v", err)
	} else if err := o.Run("systemctl", "restart", serviceUnit); err != nil {
		failure = fmt.Sprintf("restart the agent: %v", err)
	} else if !o.stayedUp() {
		failure = "the new agent did not stay up"
	}
	if failure == "" {
		return nil
	}
	if err := os.Rename(previous, current); err != nil {
		return fmt.Errorf("%s, and restoring %s failed: %v", failure, o.CurrentVersion, err)
	}
	_ = o.Run(current, "install-service")
	_ = o.Run("systemctl", "restart", serviceUnit)
	return fmt.Errorf("%s; rolled back to %s", failure, o.CurrentVersion)
}

func (o Options) stayedUp() bool {
	o.Sleep(o.Settle)
	first, err := o.Output("systemctl", "show", serviceUnit, "-p", "ActiveState", "-p", "MainPID")
	if err != nil || !running(first) {
		return false
	}
	o.Sleep(5 * time.Second)
	second, err := o.Output("systemctl", "show", serviceUnit, "-p", "ActiveState", "-p", "MainPID")
	return err == nil && running(second) && properties(second)["MainPID"] == properties(first)["MainPID"]
}

func properties(output string) map[string]string {
	found := map[string]string{}
	for line := range strings.SplitSeq(output, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			found[key] = value
		}
	}
	return found
}

func running(output string) bool {
	found := properties(output)
	return found["ActiveState"] == "active" && found["MainPID"] != "" && found["MainPID"] != "0"
}

func (o Options) writeStatus(version, message string) {
	if o.StatusPath == "" {
		return
	}
	if len(message) > 300 {
		message = message[:300]
	}
	raw, err := json.Marshal(Status{Version: version, Message: message, At: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return
	}
	temporary := o.StatusPath + ".tmp"
	if os.WriteFile(temporary, raw, 0o644) == nil {
		_ = os.Rename(temporary, o.StatusPath)
	}
}

func isNewer(target, current string) (bool, error) {
	if !versionPattern.MatchString(current) {
		return false, fmt.Errorf("the running agent has no release version (%q)", current)
	}
	left := strings.Split(target, ".")
	right := strings.Split(current, ".")
	for index := range left {
		a, _ := strconv.Atoi(left[index])
		b, _ := strconv.Atoi(right[index])
		if a != b {
			return a > b, nil
		}
	}
	return false, nil
}

func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) {
	if directory, err := os.Open(path); err == nil {
		_ = directory.Sync()
		directory.Close()
	}
}
