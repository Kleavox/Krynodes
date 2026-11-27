package stacks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestAContainedImageFromTheServerItselfIsRefused(t *testing.T) {
	previousLookup, previousInterfaces := lookupIP, interfaceIPs
	t.Cleanup(func() { lookupIP, interfaceIPs = previousLookup, previousInterfaces })
	interfaceIPs = func() []net.IP { return []net.IP{net.ParseIP("203.0.113.9"), net.ParseIP("10.88.37.2")} }
	lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "127.0.0.1.nip.example.test":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "own.example.test":
			return []net.IP{net.ParseIP("203.0.113.9")}, nil
		case "registry.example.test", "1a.example.test":
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		case "empty.example.test":
			return nil, nil
		}
		return nil, errors.New("no such host")
	}
	dir := t.TempDir()
	try := func(image string) error {
		_, config := fixture(t, "plain", dir)
		appOf(config)["image"] = image
		return Vet(config, dir, "contained")
	}
	if err := try("127.0.0.1.nip.example.test:5000/app:1"); err == nil || err.Error() != "service app pulls its image from 127.0.0.1.nip.example.test, which points at the server itself" {
		t.Fatalf("got %v", err)
	}
	for _, image := range []string{
		"localhost:5000/app", "LOCALHOST./app", "[::1]:5000/app", "169.254.169.254/latest/app",
		"203.0.113.9:5000/app", "10.88.37.2/app", "own.example.test/app",
		"[fd00::1%eth0]:5000/app", "2130706433:5000/app", "0x7f.1/app", "127.1:5000/app", "0177.0.0.1/app",
	} {
		if err := try(image); err == nil || !strings.Contains(err.Error(), "the server itself") {
			t.Errorf("%s: %v", image, err)
		}
	}
	for _, image := range []string{"registry.example.test/app:1", "1a.example.test/app", "203.0.113.7/app", "nginx:1.27", "library/nginx"} {
		if err := try(image); err != nil {
			t.Errorf("%s is elsewhere: %v", image, err)
		}
	}
	for _, host := range []string{"missing.example.test", "empty.example.test"} {
		if err := try(host + "/app:1"); err == nil || err.Error() != "could not resolve registry "+host+" for service app" {
			t.Errorf("a registry that does not resolve is refused: %v", err)
		}
	}
}

func useOwner(t *testing.T) map[string][2]int {
	t.Helper()
	previous := chown
	t.Cleanup(func() { chown = previous })
	owned := map[string][2]int{}
	chown = func(path string, uid, gid int) error {
		owned[path] = [2]int{uid, gid}
		return nil
	}
	return owned
}

func composeWrites(t *testing.T, output string, prepare func(dir string)) func(context.Context, string, ...string) ([]byte, int, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		dir := args[slices.Index(args, "--project-directory")+1]
		if prepare != nil {
			prepare(dir)
		}
		if output != "" {
			if err := os.WriteFile(filepath.Join(dir, "out.json"), []byte(output), 0o600); err != nil {
				t.Errorf("writing out.json: %v", err)
			}
		}
		return []byte("WARNING: the attribute version is obsolete\n{\"name\":\"stdout is never read\"}\n"), 0, nil
	}
}

func TestNormaliseRunsComposeAsItsOwnUserInAFolderOfItsOwn(t *testing.T) {
	owned := useOwner(t)
	var argv []string
	var seen map[string]string
	dir := ""
	write := composeWrites(t, `{"name":"web","services":{}}`, nil)
	run := func(ctx context.Context, name string, args ...string) ([]byte, int, error) {
		argv = append([]string{name}, args...)
		dir = args[slices.Index(args, "--project-directory")+1]
		seen = map[string]string{}
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			body, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
			seen[entry.Name()] = string(body)
		}
		if info, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
			t.Errorf("the folder is 0700: %v", err)
		}
		return write(ctx, name, args...)
	}
	config, err := Normalise(context.Background(), run, "web", []byte("services: {}\n"), []byte("A=1\n"))
	if err != nil || config["name"] != "web" {
		t.Fatalf("the config comes from out.json, not stdout: %#v %v", config, err)
	}
	want := []string{
		"setpriv", "--reuid=2147418112", "--regid=2147418112", "--clear-groups",
		"env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + dir,
		"docker", "compose", "--project-name", "web", "--project-directory", dir, "-f", filepath.Join(dir, "compose.yaml"),
		"config", "--format", "json", "--no-env-resolution", "-o", filepath.Join(dir, "out.json"),
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv\n got %q\nwant %q", argv, want)
	}
	if len(seen) != 2 || seen["compose.yaml"] != "services: {}\n" || seen[".env"] != "A=1\n" {
		t.Fatalf("the folder holds only the copies: %#v", seen)
	}
	for _, path := range []string{dir, filepath.Join(dir, "compose.yaml"), filepath.Join(dir, ".env")} {
		if owned[path] != [2]int{2147418112, 2147418112} {
			t.Errorf("%s belongs to the compose user: %v", path, owned[path])
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the folder is removed afterwards: %v", err)
	}
	if _, err := Normalise(context.Background(), run, "web", []byte("services: {}\n"), nil); err != nil || len(seen) != 1 {
		t.Fatalf("no .env without one: %#v %v", seen, err)
	}
}

func TestNormaliseReadsOnlyItsOwnSmallFile(t *testing.T) {
	useOwner(t)
	failing := func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		dir := args[slices.Index(args, "--project-directory")+1]
		return []byte("open " + dir + "/compose.yaml: " + strings.Repeat("x", 1000)), 1, errors.New("exit status 1")
	}
	_, err := Normalise(context.Background(), failing, "web", []byte("x"), nil)
	message := strings.TrimPrefix(err.Error(), "compose could not read the file: ")
	if err == nil || message == err.Error() || len(message) > 300 || !strings.HasPrefix(message, "open ./compose.yaml") || strings.Contains(err.Error(), os.TempDir()) {
		t.Fatalf("the error is clipped and names no temporary folder: %v", err)
	}
	if _, err := Normalise(context.Background(), composeWrites(t, `{"name":"`+strings.Repeat("a", 64<<10)+`"}`, nil), "web", []byte("x"), nil); err == nil || err.Error() != "compose returned more than 64 KB" {
		t.Fatalf("got %v", err)
	}
	for _, output := range []string{"", "no json here", "null", "[]"} {
		if _, err := Normalise(context.Background(), composeWrites(t, output, nil), "web", []byte("x"), nil); err == nil || err.Error() != "compose did not return a readable file" {
			t.Fatalf("%q: got %v", output, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(outside, []byte(`{"name":"web"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := false
	link := func(dir string) { linked = os.Symlink(outside, filepath.Join(dir, "out.json")) == nil }
	_, err = Normalise(context.Background(), composeWrites(t, "", link), "web", []byte("x"), nil)
	if !linked {
		t.Skip("symlinks are not available here")
	}
	if err == nil || err.Error() != "compose did not return a readable file" {
		t.Fatalf("a linked out.json is not followed: %v", err)
	}
}

func TestTheEnvNeverReachesAFailureMessage(t *testing.T) {
	useOwner(t)
	env := "TOKEN=s3cr3t-value\nthis line is not valid\nPIN=\"9876\"\nA=1\nex\nexport NOTE=n0te-value # prod\nCODE='c0de' # x\n"
	said := "failed to read .env: line 2: unexpected character \"this line is not valid\"; TOKEN is s3cr3t-value, PIN 9876, NOTE n0te-value, CODE c0de; exit 1"
	echo := func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte(said), 1, errors.New("exit status 1")
	}
	clean := func(where string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", where)
		}
		for _, secret := range []string{"s3cr3t-value", "this line is not valid", "9876", "n0te-value", "c0de"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: %q reached the message: %v", where, secret, err)
			}
		}
		if !strings.Contains(err.Error(), "exit 1") || !strings.Contains(err.Error(), "failed to read .env") {
			t.Fatalf("%s: the rest of the message was lost: %v", where, err)
		}
	}
	_, err := Normalise(context.Background(), echo, "web", []byte("services: {}\n"), []byte(env))
	clean("Normalise", err)
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NormaliseFull(context.Background(), echo, "web", folder, folder)
	clean("NormaliseFull", err)
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	f.fail(".env start", said)
	_, err = e.do(t, command("stack", "web", "start", nil))
	clean("start", err)
	f = newFake()
	f.config = strings.Replace(plainConfig, `"image":"nginx:1.27"`, `"image":"nginx:1.27","runtime":"s3cr3t-value"`, 1)
	e = testEnv(t, f)
	dir = managed(t, e, saving("contained", ""))
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = e.do(t, command("stack", "web", "start", nil))
	if err == nil || err.Error() != "service app asks for the runtime …" {
		t.Fatalf("vet: %v", err)
	}
}

func TestADockerStartFailureHidesTheStacksEnv(t *testing.T) {
	env := "export TOKEN=s3cr3t-token # prod\nPIN=\"9876\" # pin\n"
	said := "Error response from daemon: secret s3cr3t-token and pin 9876 refused"
	clean := func(where string, text string) {
		t.Helper()
		if strings.Contains(text, "s3cr3t-token") || strings.Contains(text, "9876") || !strings.Contains(text, "Error response from daemon") {
			t.Fatalf("%s: %s", where, text)
		}
	}
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600)
	f.on(stackLabels, "web\t/srv/web\n")
	f.fail("docker start -- web-app-1", said)
	_, err := e.do(t, command("container", "web-app-1", "start", nil))
	if err == nil {
		t.Fatal("no error")
	}
	clean("managed", err.Error())
	from := t.TempDir()
	os.WriteFile(filepath.Join(from, ".env"), []byte(env), 0o600)
	f.on(stackLabels, "other\t"+from+"\n")
	f.fail("docker restart -- other-app-1", said)
	_, err = e.do(t, command("container", "other-app-1", "restart", nil))
	if err == nil {
		t.Fatal("no error")
	}
	clean("by its folder", err.Error())
	f = newFake()
	e = testEnv(t, f)
	from = foreignStack(t, f)
	os.WriteFile(filepath.Join(from, ".env"), []byte(env), 0o600)
	f.on("{{.ID}}\t{{.Names}}", "id-1\tweb-app-1\n")
	f.fail(" up -d", "port is already allocated")
	f.fail("docker start -- id-1", said)
	_, err = e.do(t, command("stack", "web", "adopt", map[string]string{"access": "full"}))
	if err == nil || !strings.Contains(err.Error(), "did not start again") {
		t.Fatalf("adopt: %v", err)
	}
	clean("start again", err.Error())
}

func TestTheRunFileIsPrivateEverywhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are Linux only")
	}
	private := func(where, path string) {
		t.Helper()
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", where, info, err)
		}
	}
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	run := filepath.Join(dir, runFile)
	if err := e.prepare(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	private("prepare", run)
	os.Chmod(run, 0o640)
	keep(dir).put()
	private("put back", run)
	os.Chmod(run, 0o640)
	_, problems, _ := Uninstall(context.Background(), hostOf(t, f), e.State, false)
	target := filepath.Join(filepath.Dir(e.State), "krynodes-stacks", "web")
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(target)) })
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	private("moved", filepath.Join(target, runFile))
}

func TestAContainedStackNeedsDockersBootGuard(t *testing.T) {
	prepared := func(f *fake, access string) (Env, error) {
		e := testEnv(t, f)
		managed(t, e, saving(access, ""))
		return e, e.prepare(context.Background(), "web")
	}
	dropIn := func(e Env) string {
		return filepath.Join(e.Platform.Root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")
	}

	e, err := prepared(newFake(), "contained")
	if err != nil {
		t.Fatalf("a server whose Docker runs the guard: %v", err)
	}
	if _, err := os.Stat(dropIn(e)); err != nil {
		t.Fatalf("the drop-in is put in place by the deploy: %v", err)
	}

	f := newFake()
	e = testEnv(t, f)
	f.on(loadedDocker, "LoadState=not-found\n")
	managed(t, e, saving("contained", ""))
	if err := e.prepare(context.Background(), "web"); err == nil || err.Error() != "Contained stacks need Docker's boot guard, and this server's Docker has no docker.service." {
		t.Fatalf("no docker.service: %v", err)
	}
	if _, err := os.Stat(dropIn(e)); err == nil {
		t.Fatal("nothing is written for a Docker that has no unit")
	}
	e.State = t.TempDir()
	managed(t, e, saving("full", ""))
	if err := e.prepare(context.Background(), "web"); err != nil {
		t.Fatalf("a Full stack does not need the boot guard: %v", err)
	}

	f = newFake()
	e = testEnv(t, f)
	e.Platform.Executable = ""
	managed(t, e, saving("contained", ""))
	if err := e.prepare(context.Background(), "web"); err == nil || !strings.Contains(err.Error(), "the guard drop-in is missing or overridden") {
		t.Fatalf("a drop-in that cannot be written: %v", err)
	}

	f = newFake()
	e = testEnv(t, f)
	f.on(guardedDocker, "ExecStartPre=\n")
	f.on("show -p DropInPaths docker.service", "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf /etc/systemd/system/docker.service.d/override.conf\n")
	managed(t, e, saving("contained", ""))
	if err := e.prepare(context.Background(), "web"); err == nil || !strings.Contains(err.Error(), "the guard drop-in is missing or overridden") || !strings.Contains(err.Error(), "override.conf") {
		t.Fatalf("an override that resets ExecStartPre: %v", err)
	}
}

func TestStaleComposeFoldersAreClearedAtStart(t *testing.T) {
	temp := t.TempDir()
	for _, folder := range []string{"kry-compose-1", "kry-compose-2", "other-1"} {
		os.MkdirAll(filepath.Join(temp, folder), 0o700)
		os.WriteFile(filepath.Join(temp, folder, ".env"), []byte("TOKEN=first\n"), 0o600)
	}
	os.WriteFile(filepath.Join(temp, "kry-compose-file"), nil, 0o600)
	ClearTemp(temp)
	entries, _ := os.ReadDir(temp)
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	if !slices.Equal(left, []string{"kry-compose-file", "other-1"}) {
		t.Fatalf("left %q", left)
	}
}

type firewallLog struct {
	calls   []string
	respond func(call string) (string, error)
}

func (f *firewallLog) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, call)
	output, err := f.respond(call)
	if err != nil {
		return []byte(output), 1, err
	}
	return []byte(output), 0, nil
}

func ipv6(t *testing.T, off bool) {
	t.Helper()
	previous := ipv6Off
	t.Cleanup(func() { ipv6Off = previous })
	ipv6Off = func() bool { return off }
}

type tables struct {
	chains map[string][]string
	calls  []string
	spell  func(rule string) string
	deaf   bool
	stuck  string
	reads  int
	rival  int
}

func newTables() *tables {
	return &tables{chains: map[string][]string{"iptables INPUT": nil, "ip6tables INPUT": nil}}
}

func (s *tables) rules(tool, chain string) []string { return s.chains[tool+" "+chain] }

func (s *tables) seed(tool, chain string, rules ...string) { s.chains[tool+" "+chain] = rules }

func (s *tables) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	s.calls = append(s.calls, strings.Join(append([]string{name}, args...), " "))
	refused := func(said string) ([]byte, int, error) {
		return []byte(said), 1, errors.New("exit status 1")
	}
	args = args[1:]
	key := name + " " + args[1]
	rules, have := s.chains[key]
	rest := strings.Join(args[2:], " ")
	switch args[0] {
	case "-N":
		if have {
			return refused("iptables: Chain already exists.")
		}
		s.chains[key] = nil
	case "-C":
		if !have || !slices.Contains(rules, rest) {
			return refused("iptables: Bad rule (does a matching rule exist in that chain?).")
		}
	case "-A":
		if !have {
			return refused("iptables: No chain/target/match by that name.")
		}
		s.chains[key] = append(rules, rest)
	case "-I":
		at, _, _ := strings.Cut(rest, " ")
		place, _ := strconv.Atoi(at)
		if !have || place < 1 || place > len(rules)+1 {
			return refused("iptables: Index of insertion too big.")
		}
		rule := strings.TrimPrefix(rest, at+" ")
		if s.deaf && strings.HasSuffix(rule, "-j RETURN") {
			place = len(rules) + 1
		}
		s.chains[key] = slices.Insert(rules, place-1, rule)
	case "-D":
		at := slices.Index(rules, rest)
		if at < 0 || (s.stuck != "" && rules[at] == s.stuck) {
			return refused("iptables: Bad rule (does a matching rule exist in that chain?).")
		}
		s.chains[key] = slices.Delete(rules, at, at+1)
	case "-F":
		s.chains[key] = nil
	case "-X":
		delete(s.chains, key)
	case "-S":
		if !have {
			return refused("iptables: No chain/target/match by that name.")
		}
		if s.reads++; s.reads == s.rival {
			rules = slices.Insert(rules, 0, wantDrops["iptables"][0])
			s.chains[key] = rules
		}
		listed := "-N " + args[1] + "\n"
		for _, rule := range rules {
			if s.spell != nil {
				rule = s.spell(rule)
			}
			listed += "-A " + args[1] + " " + rule + "\n"
		}
		return []byte(listed), 0, nil
	}
	return nil, 0, nil
}

func (s *tables) changes() []string {
	return slices.DeleteFunc(slices.Clone(s.calls), func(call string) bool {
		return !slices.ContainsFunc([]string{" -A ", " -I ", " -D ", " -F ", " -X "}, func(verb string) bool { return strings.Contains(call, verb) })
	})
}

var (
	establishedReturn = "-i krc+ -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
	sameBridgeReturn  = "-i krc+ -o krc+ -j RETURN"
	dockersOwnReturn  = "-j RETURN"
	wantDrops         = map[string][]string{
		"iptables": {
			"-i krc+ -d 10.0.0.0/8 -j DROP", "-i krc+ -d 172.16.0.0/12 -j DROP", "-i krc+ -d 192.168.0.0/16 -j DROP",
			"-i krc+ -d 100.64.0.0/10 -j DROP", "-i krc+ -d 169.254.0.0/16 -j DROP", "-i krc+ -d 198.18.0.0/15 -j DROP",
			"-i krc+ -d 100.100.100.200 -j DROP", "-i krc+ -d 10.88.0.0/16 -j DROP",
			"-i krc+ -m conntrack --ctstate DNAT --ctorigdst 10.88.0.0/16 -j DROP",
		},
		"ip6tables": {
			"-i krc+ -d fc00::/7 -j DROP", "-i krc+ -d fe80::/10 -j DROP", "-i krc+ -d fd00:ec2::254 -j DROP",
			"-i krc+ -d fd88:88::/64 -j DROP",
			"-i krc+ -m conntrack --ctstate DNAT --ctorigdst fd88:88::/64 -j DROP",
		},
	}
)

func TestGuardKeepsContainedBridgesOffTheServer(t *testing.T) {
	useResolvers(t, "", "")
	ipv6(t, false)
	fresh := newTables()
	if err := Guard(context.Background(), fresh.run); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if got := fresh.rules(tool, "KRY-CONTAINED"); !slices.Equal(got, []string{"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-j DROP"}) {
			t.Fatalf("%s KRY-CONTAINED %q", tool, got)
		}
		if got := fresh.rules(tool, "INPUT"); !slices.Equal(got, []string{"-i krc+ -j KRY-CONTAINED"}) {
			t.Fatalf("%s INPUT %q", tool, got)
		}
	}

	fresh.calls = nil
	if err := Guard(context.Background(), fresh.run); err != nil {
		t.Fatal(err)
	}
	if changes := fresh.changes(); len(changes) > 0 {
		t.Fatalf("a second pass only checks: %q", changes)
	}

	missing := errors.New("exit status 1")
	refused := &firewallLog{respond: func(call string) (string, error) {
		if strings.Contains(call, " -C ") || strings.Contains(call, " -I INPUT") {
			return "iptables: No chain/target/match by that name.", missing
		}
		return "", nil
	}}
	if err := Guard(context.Background(), refused.run); err == nil || !strings.Contains(err.Error(), "No chain") {
		t.Fatalf("a rule that does not go in is reported: %v", err)
	}
}

func TestGuardReturnsEstablishedAndSameBridgeFirst(t *testing.T) {
	useResolvers(t, "", "")
	ipv6(t, false)
	above := func(t *testing.T, s *tables, tool string) {
		t.Helper()
		rules := s.rules(tool, "DOCKER-USER")
		if len(rules) < 2 || rules[0] != establishedReturn || rules[1] != sameBridgeReturn {
			t.Fatalf("%s DOCKER-USER does not start with the two RETURNs: %q", tool, rules)
		}
		for _, once := range []string{establishedReturn, sameBridgeReturn} {
			count := 0
			for _, rule := range rules {
				if rule == once {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("%s: %q is there %d times: %q", tool, once, count, rules)
			}
		}
		for _, drop := range wantDrops[tool] {
			if at := slices.Index(rules, drop); at < 2 {
				t.Fatalf("%s: %q sits at %d, not below the RETURNs: %q", tool, drop, at, rules)
			}
		}
	}
	both := []string{"iptables", "ip6tables"}

	fresh := newTables()
	if err := Guard(context.Background(), fresh.run); err != nil {
		t.Fatal(err)
	}
	for _, tool := range both {
		above(t, fresh, tool)
	}

	older := newTables()
	older.seed("iptables", "DOCKER-USER",
		"-i krc+ -m conntrack --ctstate DNAT --ctorigdst 10.88.0.0/16 -j DROP", "-i krc+ -d 10.88.0.0/16 -j DROP",
		"-i krc+ -d 100.100.100.200 -j DROP", "-i krc+ -d 169.254.0.0/16 -j DROP", dockersOwnReturn)
	older.seed("ip6tables", "DOCKER-USER",
		"-i krc+ -m conntrack --ctstate DNAT --ctorigdst fd88:88::/64 -j DROP", "-i krc+ -d fd88:88::/64 -j DROP",
		"-i krc+ -d fd00:ec2::254 -j DROP", dockersOwnReturn)
	if err := Guard(context.Background(), older.run); err != nil {
		t.Fatal(err)
	}
	for _, tool := range both {
		above(t, older, tool)
		if rules := older.rules(tool, "DOCKER-USER"); rules[len(rules)-1] != dockersOwnReturn {
			t.Fatalf("%s: Docker's own RETURN stays last: %q", tool, rules)
		}
	}

	grown := newTables()
	if err := Guard(context.Background(), grown.run); err != nil {
		t.Fatal(err)
	}
	for _, tool := range both {
		rules := grown.rules(tool, "DOCKER-USER")
		grown.seed(tool, "DOCKER-USER", slices.DeleteFunc(slices.Clone(rules), func(rule string) bool { return rule == wantDrops[tool][0] })...)
	}
	if err := Guard(context.Background(), grown.run); err != nil {
		t.Fatal(err)
	}
	for _, tool := range both {
		above(t, grown, tool)
		if count := len(grown.rules(tool, "DOCKER-USER")); count != 2+len(wantDrops[tool]) {
			t.Fatalf("%s: %d rules after a drop came back", tool, count)
		}
	}
}

func TestGuardDropsEveryPrivateRange(t *testing.T) {
	useResolvers(t, "", "")
	ipv6(t, false)
	s := newTables()
	if err := Guard(context.Background(), s.run); err != nil {
		t.Fatal(err)
	}
	for tool, want := range wantDrops {
		got := slices.Clone(s.rules(tool, "DOCKER-USER")[2:])
		slices.Sort(got)
		want = slices.Clone(want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s drops\n got %q\nwant %q", tool, got, want)
		}
	}
	for _, range4 := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "198.18.0.0/15", "100.100.100.200"} {
		if !slices.Contains(s.rules("iptables", "DOCKER-USER"), "-i krc+ -d "+range4+" -j DROP") {
			t.Errorf("%s is not dropped", range4)
		}
	}
	for _, range6 := range []string{"fc00::/7", "fe80::/10", "fd00:ec2::254"} {
		if !slices.Contains(s.rules("ip6tables", "DOCKER-USER"), "-i krc+ -d "+range6+" -j DROP") {
			t.Errorf("%s is not dropped", range6)
		}
	}
}

func TestGuardLeavesIPv6AloneOnlyWhenTheServerHasItOff(t *testing.T) {
	missing := errors.New("exit status 1")
	broken := func(call string) (string, error) {
		if strings.HasPrefix(call, "ip6tables") {
			return "", errors.New(`exec: "ip6tables": executable file not found in $PATH`)
		}
		if strings.Contains(call, " -C ") {
			return "", missing
		}
		if strings.HasSuffix(call, " -S DOCKER-USER") {
			return guardedChain, nil
		}
		return "", nil
	}
	useResolvers(t, "", "")
	ipv6(t, true)
	off := &firewallLog{respond: broken}
	if err := Guard(context.Background(), off.run); err != nil {
		t.Fatalf("IPv6 is off, so ip6tables is not needed: %v", err)
	}
	if slices.ContainsFunc(off.calls, func(call string) bool { return strings.HasPrefix(call, "ip6tables") }) {
		t.Fatalf("calls %q", off.calls)
	}
	ipv6(t, false)
	on := &firewallLog{respond: broken}
	err := Guard(context.Background(), on.run)
	if err == nil || !strings.HasPrefix(err.Error(), "IPv6 is on but ip6tables does not work") || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("a broken ip6tables names the cause: %v", err)
	}
}

func TestGuardFailsWhenTheOrderCannotBeRead(t *testing.T) {
	useResolvers(t, "", "")
	ipv6(t, true)
	unreadable := &firewallLog{respond: func(call string) (string, error) {
		if strings.Contains(call, " -S DOCKER-USER") {
			return "iptables: No chain/target/match by that name.", errors.New("exit status 1")
		}
		return "", nil
	}}
	if err := Guard(context.Background(), unreadable.run); err == nil || !strings.Contains(err.Error(), "DOCKER-USER") {
		t.Fatalf("a guard that cannot tell its order is not a guard: %v", err)
	}
}

func TestUnguardTakesTheGuardAway(t *testing.T) {
	jumps := map[string]int{}
	log := &firewallLog{respond: func(call string) (string, error) {
		switch {
		case strings.HasSuffix(call, " -C INPUT -i krc+ -j KRY-CONTAINED"):
			jumps[call]++
			if jumps[call] > 1 {
				return "", errors.New("exit status 1")
			}
		case strings.HasSuffix(call, " -S DOCKER-USER"):
			return "-N DOCKER-USER\n-A DOCKER-USER -i krc+ -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n-A DOCKER-USER -i krc+ -o krc+ -j RETURN\n-A DOCKER-USER -d 169.254.169.254/32 -i krc+ -j DROP\n-A DOCKER-USER -j RETURN\n-A DOCKER-USER -d 10.88.0.0/16 -i krc+ -j DROP\n-A DOCKER-USER -i krc+ -m conntrack --ctorigdst 10.88.0.0/16 --ctstate DNAT -j DROP\n-A DOCKER-USER -i br-1 -j DROP\n", nil
		}
		return "", nil
	}}
	Unguard(context.Background(), log.run)
	var want []string
	for _, tool := range []string{"iptables", "ip6tables"} {
		want = append(want,
			tool+" -w -C INPUT -i krc+ -j KRY-CONTAINED",
			tool+" -w -D INPUT -i krc+ -j KRY-CONTAINED",
			tool+" -w -C INPUT -i krc+ -j KRY-CONTAINED",
			tool+" -w -F KRY-CONTAINED",
			tool+" -w -X KRY-CONTAINED",
			tool+" -w -S DOCKER-USER",
			tool+" -w -D DOCKER-USER -i krc+ -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
			tool+" -w -D DOCKER-USER -i krc+ -o krc+ -j RETURN",
			tool+" -w -D DOCKER-USER -d 169.254.169.254/32 -i krc+ -j DROP",
			tool+" -w -D DOCKER-USER -d 10.88.0.0/16 -i krc+ -j DROP",
			tool+" -w -D DOCKER-USER -i krc+ -m conntrack --ctorigdst 10.88.0.0/16 --ctstate DNAT -j DROP",
		)
	}
	if !slices.Equal(log.calls, want) {
		t.Fatalf("calls\n got %q\nwant %q", log.calls, want)
	}
}

func TestUnguardRemovesTheReturns(t *testing.T) {
	s := newTables()
	for _, tool := range []string{"iptables", "ip6tables"} {
		s.seed(tool, "DOCKER-USER", "-i eth9 -j ACCEPT", establishedReturn, sameBridgeReturn, wantDrops[tool][0], dockersOwnReturn)
		s.seed(tool, "KRY-CONTAINED", "-j DROP")
		s.seed(tool, "INPUT", "-i krc+ -j KRY-CONTAINED")
	}
	Unguard(context.Background(), s.run)
	for _, tool := range []string{"iptables", "ip6tables"} {
		if got := s.rules(tool, "DOCKER-USER"); !slices.Equal(got, []string{"-i eth9 -j ACCEPT", dockersOwnReturn}) {
			t.Fatalf("%s DOCKER-USER keeps only what is not Krynodes: %q", tool, got)
		}
		if _, there := s.chains[tool+" KRY-CONTAINED"]; there || len(s.rules(tool, "INPUT")) != 0 {
			t.Fatalf("%s: the chain and its jump are gone", tool)
		}
	}
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "guard-lock")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	GuardLock = filepath.Join(dir, "guard.lock")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func useLock(t *testing.T) {
	t.Helper()
	was := GuardLock
	t.Cleanup(func() { GuardLock = was })
	GuardLock = filepath.Join(t.TempDir(), "guard.lock")
}

func useResolvers(t *testing.T, etc, systemd string) {
	t.Helper()
	dir := t.TempDir()
	previousEtc, previousSystemd := resolvConf, resolvSystemd
	t.Cleanup(func() { resolvConf, resolvSystemd = previousEtc, previousSystemd })
	resolvConf, resolvSystemd = filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "systemd-resolv.conf")
	rewriteResolvers(t, etc, systemd)
}

func rewriteResolvers(t *testing.T, etc, systemd string) {
	t.Helper()
	for path, body := range map[string]string{resolvConf: etc, resolvSystemd: systemd} {
		if body == "" {
			os.Remove(path)
		} else if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func resolverRules(addresses ...string) []string {
	var rules []string
	for _, address := range addresses {
		rules = append(rules, "-i krc+ -d "+address+" -p udp --dport 53 -j RETURN", "-i krc+ -d "+address+" -p tcp --dport 53 -j RETURN")
	}
	return rules
}

func sorted(rules []string) []string {
	rules = slices.Clone(rules)
	slices.Sort(rules)
	return rules
}

func guardsWith(t *testing.T, s *tables, tool string, resolvers []string) {
	t.Helper()
	if err := Guard(context.Background(), s.run); err != nil {
		t.Fatal(err)
	}
	rules := s.rules(tool, "DOCKER-USER")
	below := 2 + len(resolvers)
	if len(rules) != below+len(wantDrops[tool]) || rules[0] != establishedReturn || rules[1] != sameBridgeReturn {
		t.Fatalf("%s DOCKER-USER %q", tool, rules)
	}
	if !slices.Equal(sorted(rules[2:below]), sorted(resolvers)) || !slices.Equal(sorted(rules[below:]), sorted(wantDrops[tool])) {
		t.Fatalf("%s: the resolvers sit above the drops, and nothing else sits there: %q", tool, rules)
	}
}

func TestGuardKeepsTheServersResolversReachable(t *testing.T) {
	ipv6(t, false)
	useResolvers(t, "# the resolvers of a cloud server\nnameserver 100.100.2.136 # first\nnameserver 10.0.0.2\nnameserver 1.1.1.1\nnameserver 127.0.0.1\nnameserver fd00::53\nnameserver 2606:4700:4700::1111\nnameserver fe80::1%eth0\nsearch example.test\n", "")
	s := newTables()
	guardsWith(t, s, "iptables", resolverRules("100.100.2.136", "10.0.0.2"))
	guardsWith(t, s, "ip6tables", resolverRules("fd00::53", "fe80::1"))

	s.calls = nil
	guardsWith(t, s, "iptables", resolverRules("100.100.2.136", "10.0.0.2"))
	if changes := s.changes(); len(changes) > 0 {
		t.Fatalf("a second pass only checks: %q", changes)
	}

	halfway := newTables()
	halfway.seed("iptables", "DOCKER-USER", wantDrops["iptables"][0], establishedReturn, resolverRules("10.0.0.2")[0], sameBridgeReturn, dockersOwnReturn)
	if err := Guard(context.Background(), halfway.run); err != nil {
		t.Fatal(err)
	}
	rules := halfway.rules("iptables", "DOCKER-USER")
	if len(rules) != 2+4+len(wantDrops["iptables"])+1 || rules[0] != establishedReturn || rules[1] != sameBridgeReturn ||
		!slices.Equal(sorted(rules[2:6]), sorted(resolverRules("100.100.2.136", "10.0.0.2"))) || rules[len(rules)-1] != dockersOwnReturn {
		t.Fatalf("a pass that stopped halfway is put right, and Docker's own RETURN stays last: %q", rules)
	}
}

func TestAResolverThatGoesLosesItsRules(t *testing.T) {
	ipv6(t, true)
	useResolvers(t, "nameserver 100.100.2.136\n", "")
	s := newTables()
	guardsWith(t, s, "iptables", resolverRules("100.100.2.136"))
	rewriteResolvers(t, "nameserver 10.0.0.2\n", "")
	guardsWith(t, s, "iptables", resolverRules("10.0.0.2"))
	rewriteResolvers(t, "nameserver 9.9.9.9\n", "")
	guardsWith(t, s, "iptables", nil)
}

func TestTheSystemdResolverFileIsReadWhenEtcHoldsOnlyTheStub(t *testing.T) {
	ipv6(t, true)
	useResolvers(t, "nameserver 127.0.0.53\noptions edns0\n", "nameserver 10.0.0.2\n")
	s := newTables()
	guardsWith(t, s, "iptables", resolverRules("10.0.0.2"))
	rewriteResolvers(t, "nameserver 10.1.2.3\nnameserver 127.0.0.53\n", "nameserver 10.0.0.2\n")
	guardsWith(t, s, "iptables", resolverRules("10.1.2.3"))
	rewriteResolvers(t, "nameserver 127.0.0.53\n", "")
	guardsWith(t, s, "iptables", nil)
	rewriteResolvers(t, "nameserver 127.0.0.1\n", "nameserver 10.0.0.2\n")
	guardsWith(t, s, "iptables", nil)
}

func TestAPublicResolverAddsNothing(t *testing.T) {
	ipv6(t, false)
	useResolvers(t, "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nnameserver 127.0.0.1\n", "")
	s := newTables()
	guardsWith(t, s, "iptables", nil)
	guardsWith(t, s, "ip6tables", nil)
}

func TestARuleOfOursIsRecognisedByMeaning(t *testing.T) {
	for rule, want := range map[string]string{
		"-i krc+ -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN":   "established",
		"-m conntrack --ctstate ESTABLISHED,RELATED -i krc+ -j RETURN":   "established",
		"-i krc+ -m state --state RELATED,ESTABLISHED -j RETURN":         "established",
		"-i krc+ -o krc+ -j RETURN":                                      "bridge",
		"-o krc+ -i krc+ -j RETURN":                                      "bridge",
		"-d 100.100.2.136/32 -i krc+ -p udp -m udp --dport 53 -j RETURN": "udp 100.100.2.136",
		"-d fd00::53/128 -i krc+ -p tcp -m tcp --dport 53 -j RETURN":     "tcp fd00::53",
		"-i krc+ -d 10.0.0.2 -p udp --dport 53 -j RETURN":                "udp 10.0.0.2",
	} {
		if got, ok := ownKey(rule); !ok || got != want {
			t.Errorf("%q: %q %v", rule, got, ok)
		}
	}
	for _, rule := range []string{
		dockersOwnReturn, wantDrops["iptables"][0],
		"-i krc+ -m conntrack --ctstate RELATED -j RETURN",
		"-i krc+ -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j RETURN",
		"-i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-i krc+ -o eth0 -j RETURN",
		"-s 10.0.0.0/8 -i krc+ -o krc+ -j RETURN",
		"-i krc+ -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment a_b -j RETURN",
		"-i krc+ ! -o krc+ -j RETURN",
		"-d 10.0.0.0/8 -i krc+ -p udp -m udp --dport 53 -j RETURN",
		"-d 10.0.0.2/32 -i eth0 -p udp -m udp --dport 53 -j RETURN",
		"-d 10.0.0.2/32 -i krc+ -p udp -m udp --dport 5353 -j RETURN",
	} {
		if got, ok := ownKey(rule); ok {
			t.Errorf("%q is not a rule of ours: %q", rule, got)
		}
	}
}

func TestGuardKnowsItsRETURNsByMeaningNotByWording(t *testing.T) {
	ipv6(t, false)
	useResolvers(t, "nameserver 10.0.0.2\n", "")
	for name, spell := range map[string]func(string) string{
		"another order and the conntrack match in front": func(rule string) string {
			switch rule {
			case establishedReturn:
				return "-m conntrack --ctstate ESTABLISHED,RELATED -i krc+ -j RETURN"
			case sameBridgeReturn:
				return "-o krc+ -i krc+ -j RETURN"
			}
			return rule
		},
		"the state match": func(rule string) string {
			switch rule {
			case establishedReturn:
				return "-i krc+ -m state --state RELATED,ESTABLISHED -j RETURN"
			case "-i krc+ -d 10.0.0.2 -p udp --dport 53 -j RETURN":
				return "-d 10.0.0.2/32 -i krc+ -p udp -m udp --dport 53 -j RETURN"
			}
			return rule
		},
	} {
		s := newTables()
		s.spell = spell
		stored := func() []string { return s.rules("iptables", "DOCKER-USER") }
		count := func(rule string) int {
			n := 0
			for _, one := range stored() {
				if one == rule {
					n++
				}
			}
			return n
		}
		for pass := range 4 {
			s.calls = nil
			if err := Guard(context.Background(), s.run); err != nil {
				t.Fatalf("%s, pass %d: %v", name, pass, err)
			}
			if pass > 0 && len(s.changes()) > 0 {
				t.Fatalf("%s, pass %d: a settled chain is only checked: %q", name, pass, s.changes())
			}
			if len(stored()) != 2+2+len(wantDrops["iptables"]) || stored()[0] != establishedReturn || stored()[1] != sameBridgeReturn {
				t.Fatalf("%s, pass %d: the chain does not converge: %q", name, pass, stored())
			}
		}

		s.seed("iptables", "DOCKER-USER", slices.DeleteFunc(slices.Clone(stored()), func(rule string) bool { return rule == wantDrops["iptables"][0] })...)
		if err := Guard(context.Background(), s.run); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(stored()) != 2+2+len(wantDrops["iptables"]) || stored()[0] != establishedReturn || stored()[1] != sameBridgeReturn || count(establishedReturn) != 1 || count(sameBridgeReturn) != 1 {
			t.Fatalf("%s: a repair adds nothing twice: %q", name, stored())
		}
	}
}

func TestGuardFailsLoudlyWhenItCannotPutTheRETURNsOnTop(t *testing.T) {
	ipv6(t, true)
	useResolvers(t, "", "")

	deaf := newTables()
	deaf.deaf = true
	if err := Guard(context.Background(), deaf.run); err == nil || !strings.Contains(err.Error(), "not above the drops") {
		t.Fatalf("an iptables that puts the RETURNs below the drops is a failed guard: %v", err)
	}

	const alienReturn = "-i krc+ -m state --state RELATED,ESTABLISHED -j RETURN"
	kin := newTables()
	kin.seed("iptables", "DOCKER-USER", wantDrops["iptables"][0], alienReturn, alienReturn, "-j RETURN")
	if err := Guard(context.Background(), kin.run); err != nil {
		t.Fatalf("a RETURN iptables will not match against our argv is taken away by the text it printed: %v", err)
	}
	if kept := kin.rules("iptables", "DOCKER-USER"); slices.Contains(kept, alienReturn) || kept[0] != establishedReturn || kept[1] != sameBridgeReturn || kept[len(kept)-1] != "-j RETURN" || len(kept) != 2+len(wantDrops["iptables"])+1 {
		t.Fatalf("it converges with one copy of each: %q", kept)
	}

	alien := newTables()
	alien.seed("iptables", "DOCKER-USER", wantDrops["iptables"][0], alienReturn)
	alien.stuck = alienReturn
	err := Guard(context.Background(), alien.run)
	if err == nil || !strings.Contains(err.Error(), "DOCKER-USER") {
		t.Fatalf("a RETURN that cannot be deleted is not swallowed: %v", err)
	}
	returns := 0
	for _, rule := range alien.rules("iptables", "DOCKER-USER") {
		if strings.HasSuffix(rule, "-j RETURN") {
			returns++
		}
	}
	if returns != 1 {
		t.Fatalf("nothing was added on top of a failed repair: %q", alien.rules("iptables", "DOCKER-USER"))
	}
}

func TestGuardRepairsOnceMoreWhenAnotherPassDisturbsTheOrder(t *testing.T) {
	ipv6(t, true)
	useResolvers(t, "", "")
	s := newTables()
	s.rival = 2
	if err := Guard(context.Background(), s.run); err != nil {
		t.Fatalf("a pass that finds the order disturbed repairs once more and settles: %v", err)
	}
	kept := s.rules("iptables", "DOCKER-USER")
	if kept[0] != establishedReturn || kept[1] != sameBridgeReturn || slices.Index(kept[1:], establishedReturn) >= 0 || slices.Index(kept[2:], sameBridgeReturn) >= 0 {
		t.Fatalf("one copy of each RETURN on top: %q", kept)
	}

	stubborn := newTables()
	stubborn.deaf = true
	err := Guard(context.Background(), stubborn.run)
	tries := 0
	for _, call := range stubborn.calls {
		if strings.HasSuffix(call, "-I DOCKER-USER 1 "+sameBridgeReturn) {
			tries++
		}
	}
	if err == nil || !strings.Contains(err.Error(), "not above the drops") || tries != 2 {
		t.Fatalf("a chain that stays wrong is an error after two repairs and no more: %v, %d", err, tries)
	}
}

func TestAMeshResolverGetsNoRule(t *testing.T) {
	ipv6(t, false)
	useResolvers(t, "nameserver 10.88.0.5\nnameserver fd88:88::5\nnameserver 10.0.0.2\n", "")
	s := newTables()
	guardsWith(t, s, "iptables", resolverRules("10.0.0.2"))
	guardsWith(t, s, "ip6tables", nil)
}

func TestUnguardRemovesTheResolverRules(t *testing.T) {
	s := newTables()
	s.seed("iptables", "DOCKER-USER", establishedReturn, sameBridgeReturn,
		"-d 100.100.2.136/32 -i krc+ -p udp -m udp --dport 53 -j RETURN", "-d 100.100.2.136/32 -i krc+ -p tcp -m tcp --dport 53 -j RETURN",
		wantDrops["iptables"][0], dockersOwnReturn)
	s.seed("ip6tables", "DOCKER-USER", establishedReturn, sameBridgeReturn,
		"-d fd00::53/128 -i krc+ -p udp -m udp --dport 53 -j RETURN", "-d fd00::53/128 -i krc+ -p tcp -m tcp --dport 53 -j RETURN",
		wantDrops["ip6tables"][0], dockersOwnReturn)
	Unguard(context.Background(), s.run)
	for _, tool := range []string{"iptables", "ip6tables"} {
		if got := s.rules(tool, "DOCKER-USER"); !slices.Equal(got, []string{dockersOwnReturn}) {
			t.Fatalf("%s DOCKER-USER keeps only Docker's own rule: %q", tool, got)
		}
	}
}

func composeSaying(t *testing.T, change func(dir string, app map[string]any)) func(context.Context, string, ...string) ([]byte, int, error) {
	t.Helper()
	plain, err := os.ReadFile(filepath.Join("testdata", "plain.json"))
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		dir := args[slices.Index(args, "--project-directory")+1]
		var config map[string]any
		if err := json.Unmarshal(plain, &config); err != nil {
			t.Fatal(err)
		}
		change(dir, appOf(config))
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return nil, 0, os.WriteFile(filepath.Join(dir, "out.json"), encoded, 0o600)
	}
}

func TestEnvFileRefusalNamesTheProjectPath(t *testing.T) {
	useOwner(t)
	outside := filepath.Join(t.TempDir(), "app.env")
	for _, case_ := range []struct {
		field string
		path  func(dir string) string
		want  string
	}{
		{"env_file", func(dir string) string { return filepath.Join(dir, "app.env") }, "service app reads ./app.env from the server"},
		{"label_file", func(dir string) string { return filepath.Join(dir, "app.env") }, "service app reads ./app.env from the server"},
		{"env_file", func(string) string { return outside }, "service app reads " + outside + " from the server"},
	} {
		var sandbox string
		run := composeSaying(t, func(dir string, app map[string]any) {
			sandbox = dir
			if case_.field == "env_file" {
				app[case_.field] = []any{map[string]any{"path": case_.path(dir), "required": true}}
				return
			}
			app[case_.field] = []any{case_.path(dir)}
		})
		config, err := Normalise(context.Background(), run, "web", []byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := Vet(config, t.TempDir(), "contained"); err == nil || err.Error() != case_.want || strings.Contains(err.Error(), sandbox) {
			t.Fatalf("%s: got %v, want %q", case_.field, err, case_.want)
		}
	}
}

func TestARelativeBindIsStillRefusedAfterTheRewrite(t *testing.T) {
	useOwner(t)
	run := composeSaying(t, func(dir string, app map[string]any) {
		app["volumes"] = []any{map[string]any{"type": "bind", "source": filepath.Join(dir, "data"), "target": "/data", "bind": map[string]any{}}}
	})
	config, err := Normalise(context.Background(), run, "web", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Vet(config, t.TempDir(), "contained"); err == nil || err.Error() != "service app mounts ./data from the server"+keepsData {
		t.Fatalf("a relative bind: %v", err)
	}
}

func TestOnlyThePathsUnderTheSandboxAreRewritten(t *testing.T) {
	sandbox := filepath.Join(os.TempDir(), "kry-compose-12")
	elsewhere := filepath.Join(os.TempDir(), "kry-compose-123", "app.env")
	config := map[string]any{
		"list": []any{filepath.Join(sandbox, "app.env"), elsewhere, sandbox + "-other", sandbox, "nginx:1.27"},
		"deep": map[string]any{"path": filepath.Join(sandbox, "a", "b.env"), "required": true},
	}
	got := inFolder(config, sandbox).(map[string]any)
	if list := got["list"].([]any); !slices.Equal(list, []any{"./app.env", elsewhere, sandbox + "-other", ".", "nginx:1.27"}) {
		t.Fatalf("list %q", list)
	}
	if deep := got["deep"].(map[string]any); deep["path"] != "./a/b.env" || deep["required"] != true {
		t.Fatalf("deep %v", deep)
	}
}
