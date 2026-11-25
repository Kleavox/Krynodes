package stacks

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	_, problems, _ := Uninstall(context.Background(), f.run, e.State, false)
	target := filepath.Join(filepath.Dir(e.State), "krynodes-stacks", "web")
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(target)) })
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	private("moved", filepath.Join(target, runFile))
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

func TestGuardKeepsContainedBridgesOffTheServer(t *testing.T) {
	ipv6(t, false)
	missing := errors.New("exit status 1")
	fresh := &firewallLog{respond: func(call string) (string, error) {
		if strings.Contains(call, " -C ") {
			return "iptables: Bad rule (does a matching rule exist in that chain?).", missing
		}
		return "", nil
	}}
	if err := Guard(context.Background(), fresh.run); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, tool := range []string{"iptables", "ip6tables"} {
		want = append(want,
			tool+" -w -N KRY-CONTAINED",
			tool+" -w -C KRY-CONTAINED -j DROP",
			tool+" -w -A KRY-CONTAINED -j DROP",
			tool+" -w -C KRY-CONTAINED -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			tool+" -w -I KRY-CONTAINED 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			tool+" -w -C INPUT -i krc+ -j KRY-CONTAINED",
			tool+" -w -I INPUT 1 -i krc+ -j KRY-CONTAINED",
			tool+" -w -N DOCKER-USER",
		)
	}
	drops := [][2]string{
		{"iptables", "-d 169.254.0.0/16"}, {"iptables", "-d 100.100.100.200"}, {"ip6tables", "-d fd00:ec2::254"},
		{"iptables", "-d 10.88.0.0/16"}, {"ip6tables", "-d fd88:88::/64"},
		{"iptables", "-m conntrack --ctstate DNAT --ctorigdst 10.88.0.0/16"}, {"ip6tables", "-m conntrack --ctstate DNAT --ctorigdst fd88:88::/64"},
	}
	for _, drop := range drops {
		want = append(want,
			drop[0]+" -w -C DOCKER-USER -i krc+ "+drop[1]+" -j DROP",
			drop[0]+" -w -I DOCKER-USER 1 -i krc+ "+drop[1]+" -j DROP",
		)
	}
	if !slices.Equal(fresh.calls, want) {
		t.Fatalf("calls\n got %q\nwant %q", fresh.calls, want)
	}

	settled := &firewallLog{respond: func(string) (string, error) { return "", nil }}
	if err := Guard(context.Background(), settled.run); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(settled.calls, func(call string) bool {
		return strings.Contains(call, " -A ") || strings.Contains(call, " -I ") || !strings.Contains(call, "tables -w ")
	}) || len(settled.calls) != 17 {
		t.Fatalf("a second pass only checks: %q", settled.calls)
	}

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

func TestGuardLeavesIPv6AloneOnlyWhenTheServerHasItOff(t *testing.T) {
	missing := errors.New("exit status 1")
	broken := func(call string) (string, error) {
		if strings.HasPrefix(call, "ip6tables") {
			return "", errors.New(`exec: "ip6tables": executable file not found in $PATH`)
		}
		if strings.Contains(call, " -C ") {
			return "", missing
		}
		return "", nil
	}
	ipv6(t, true)
	off := &firewallLog{respond: broken}
	if err := Guard(context.Background(), off.run); err != nil {
		t.Fatalf("IPv6 is off, so ip6tables is not needed: %v", err)
	}
	if slices.ContainsFunc(off.calls, func(call string) bool { return strings.HasPrefix(call, "ip6tables") }) || len(off.calls) != 16 {
		t.Fatalf("calls %q", off.calls)
	}
	ipv6(t, false)
	on := &firewallLog{respond: broken}
	err := Guard(context.Background(), on.run)
	if err == nil || !strings.HasPrefix(err.Error(), "IPv6 is on but ip6tables does not work") || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("a broken ip6tables names the cause: %v", err)
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
			return "-N DOCKER-USER\n-A DOCKER-USER -d 169.254.169.254/32 -i krc+ -j DROP\n-A DOCKER-USER -j RETURN\n-A DOCKER-USER -d 10.88.0.0/16 -i krc+ -j DROP\n-A DOCKER-USER -i krc+ -m conntrack --ctorigdst 10.88.0.0/16 --ctstate DNAT -j DROP\n-A DOCKER-USER -i br-1 -j DROP\n", nil
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
			tool+" -w -D DOCKER-USER -d 169.254.169.254/32 -i krc+ -j DROP",
			tool+" -w -D DOCKER-USER -d 10.88.0.0/16 -i krc+ -j DROP",
			tool+" -w -D DOCKER-USER -i krc+ -m conntrack --ctorigdst 10.88.0.0/16 --ctstate DNAT -j DROP",
		)
	}
	if !slices.Equal(log.calls, want) {
		t.Fatalf("calls\n got %q\nwant %q", log.calls, want)
	}
}
