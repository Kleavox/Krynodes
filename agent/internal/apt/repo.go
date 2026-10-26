package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	keyrings     = "/etc/apt/keyrings"
	ourKeyring   = keyrings + "/krynodes-"
	shownPackage = 20
)

type Repo struct {
	Name        string   `json:"name"`
	URI         string   `json:"uri"`
	Suites      []string `json:"suites"`
	Components  []string `json:"components"`
	Key         string   `json:"key"`
	List        string   `json:"list,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type KeyFacts struct {
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user"`
}

type RepoPreview struct {
	What       string    `json:"what"`
	Name       string    `json:"name"`
	URI        string    `json:"uri"`
	Suites     []string  `json:"suites"`
	Components []string  `json:"components"`
	File       string    `json:"file"`
	Key        *KeyFacts `json:"key"`
	Answers    bool      `json:"answers"`
	Packages   []string  `json:"packages"`
	Count      int       `json:"count"`
	Refused    *string   `json:"refused"`
}

var (
	repoName  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	suiteName = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	component = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	fullPrint = regexp.MustCompile(`^([0-9A-F]{40}|[0-9A-F]{64})$`)
)

func secure(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be fetched over HTTPS", address)
	}
	return nil
}

func sourcesFile(name string) string {
	return sourcesDir + "/" + name + ".sources"
}

func (j Job) check(repo Repo) error {
	if !repoName.MatchString(repo.Name) {
		return errors.New("a repository name has lowercase letters, digits, dots and dashes only")
	}
	parsed, err := url.Parse(repo.URI)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || strings.ContainsAny(repo.URI, " \t\n") {
		return errors.New("the address must be an http or https URL")
	}
	if len(repo.Suites) == 0 || len(repo.Suites) > 8 || len(repo.Components) == 0 || len(repo.Components) > 8 {
		return errors.New("a repository needs a release and at least one component; flat repositories are not supported")
	}
	for _, suite := range repo.Suites {
		if !suiteName.MatchString(suite) {
			return fmt.Errorf("%q is not a release name", suite)
		}
	}
	for _, part := range repo.Components {
		if !component.MatchString(part) {
			return fmt.Errorf("%q is not a component name", part)
		}
	}
	for _, taken := range []string{sourcesFile(repo.Name), sourcesDir + "/" + repo.Name + ".list"} {
		if _, err := os.Stat(at(j.Root, taken)); err == nil {
			return fmt.Errorf("a source named %s is already on this server", repo.Name)
		}
	}
	return secure(repo.Key)
}

func (j Job) resolve(ctx context.Context, repo Repo) (Repo, error) {
	if repo.List == "" {
		return repo, nil
	}
	if err := secure(repo.List); err != nil {
		return repo, err
	}
	body, err := j.Get(ctx, repo.List)
	if err != nil {
		return repo, err
	}
	lines := oneLine(string(body))
	if len(lines) == 0 {
		return repo, fmt.Errorf("%s has no deb line", repo.List)
	}
	repo.URI, repo.Suites, repo.Components = lines[0].uri, lines[0].suites, lines[0].components
	return repo, nil
}

func (j Job) key(ctx context.Context, address string) ([]byte, []Key, error) {
	if err := secure(address); err != nil {
		return nil, nil, err
	}
	body, err := j.Get(ctx, address)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch the key: %w", err)
	}
	keys, err := ReadKeys(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not an OpenPGP key: %w", address, err)
	}
	return body, keys, nil
}

func (j Job) PreviewRepo(ctx context.Context, repo Repo) RepoPreview {
	preview := RepoPreview{What: "addrepo", Name: repo.Name, File: sourcesFile(repo.Name), Packages: []string{}}
	refuse := func(err error) RepoPreview {
		preview.Refused = text(err.Error())
		return preview
	}
	repo, err := j.resolve(ctx, repo)
	preview.URI, preview.Suites, preview.Components = repo.URI, repo.Suites, repo.Components
	if err != nil {
		return refuse(err)
	}
	if err := j.check(repo); err != nil {
		return refuse(err)
	}
	_, keys, err := j.key(ctx, repo.Key)
	if err != nil {
		return refuse(err)
	}
	preview.Key = &KeyFacts{Fingerprint: keys[0].Fingerprint, User: keys[0].User}
	base := strings.TrimSuffix(repo.URI, "/") + "/dists/" + repo.Suites[0]
	for _, release := range []string{"/InRelease", "/Release"} {
		if _, err := j.Get(ctx, base+release); err == nil {
			preview.Answers = true
			break
		}
	}
	architecture, _, _ := j.Run(ctx, "dpkg", "--print-architecture")
	listing := base + "/" + repo.Components[0] + "/binary-" + strings.TrimSpace(string(architecture)) + "/Packages"
	var names []string
	if packed, err := j.Get(ctx, listing+".gz"); err == nil {
		if reader, err := gzip.NewReader(bytes.NewReader(packed)); err == nil {
			unpacked, _ := io.ReadAll(reader)
			names = packageNames(string(unpacked))
		}
	} else if plain, err := j.Get(ctx, listing); err == nil {
		names = packageNames(string(plain))
	}
	preview.Count = len(names)
	preview.Packages = append(preview.Packages, names[:min(len(names), shownPackage)]...)
	return preview
}

func packageNames(listing string) []string {
	var names []string
	for _, stanza := range stanzas(listing) {
		if name := stanza["package"]; name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (j Job) update(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	text, _, err := j.Run(ctx, "env", append([]string{"LC_ALL=C", "apt-get", "-q", "update"}, args...)...)
	if err != nil {
		return errors.New(last(string(text), err))
	}
	return nil
}

func (j Job) AddRepo(ctx context.Context, repo Repo) (string, error) {
	repo.List = ""
	if err := j.check(repo); err != nil {
		return "", err
	}
	wanted := strings.ToUpper(strings.ReplaceAll(repo.Fingerprint, " ", ""))
	if !fullPrint.MatchString(wanted) {
		return "", errors.New("the approved key fingerprint is missing")
	}
	body, keys, err := j.key(ctx, repo.Key)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(keys, func(key Key) bool { return key.Fingerprint == wanted }) {
		return "", fmt.Errorf("the key at %s has fingerprint %s, not the %s you approved; nothing was added", repo.Key, keys[0].Fingerprint, wanted)
	}
	keyring := ourKeyring + repo.Name + ".gpg"
	if bytes.Contains(body, []byte("-----BEGIN PGP")) {
		keyring = ourKeyring + repo.Name + ".asc"
	}
	file := sourcesFile(repo.Name)
	stanza := fmt.Sprintf("Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n", repo.URI, strings.Join(repo.Suites, " "), strings.Join(repo.Components, " "), keyring)
	takeBack := func(err error) (string, error) {
		os.Remove(at(j.Root, file))
		os.Remove(at(j.Root, keyring))
		return "", err
	}
	for path, content := range map[string][]byte{keyring: body, file: []byte(stanza)} {
		if err := os.MkdirAll(filepath.Dir(at(j.Root, path)), 0o755); err != nil {
			return takeBack(err)
		}
		if err := os.WriteFile(at(j.Root, path), content, 0o644); err != nil {
			return takeBack(err)
		}
	}
	if err := j.update(ctx, "-o", "Dir::Etc::sourcelist="+file, "-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0"); err != nil {
		return takeBack(err)
	}
	return file, nil
}

func (j Job) DropRepo(ctx context.Context, name, distro string) error {
	if !repoName.MatchString(name) {
		return fmt.Errorf("no source named %s", name)
	}
	var file string
	for _, source := range ReadSources(j.Root, distro, nil) {
		if source.Name != name {
			continue
		}
		if source.System || !strings.HasPrefix(source.File, sourcesDir+"/") {
			return fmt.Errorf("%s is the system's own source", name)
		}
		file = source.File
	}
	if file == "" {
		return fmt.Errorf("no source named %s", name)
	}
	body, err := os.ReadFile(at(j.Root, file))
	if err != nil {
		return err
	}
	lines := oneLine(string(body))
	if strings.HasSuffix(file, ".sources") {
		lines = deb822(string(body))
	}
	if err := os.Remove(at(j.Root, file)); err != nil {
		return err
	}
	for _, found := range lines {
		if strings.HasPrefix(found.key, ourKeyring) && !strings.Contains(found.key, "/..") {
			os.Remove(at(j.Root, found.key))
		}
	}
	j.update(ctx)
	return nil
}

func (j Job) Refresh(ctx context.Context) error {
	if err := j.update(ctx); err != nil {
		return err
	}
	stamp := at(j.Root, "/var/lib/apt/periodic/update-success-stamp")
	if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
		return err
	}
	now := j.Now()
	if err := os.WriteFile(stamp, nil, 0o644); err != nil {
		return err
	}
	return os.Chtimes(stamp, now, now)
}
