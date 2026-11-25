package stacks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func fixture(t *testing.T, name, dir string) (string, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	normalised, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	escaped, _ := json.Marshal(dir)
	text := strings.ReplaceAll(string(normalised), "@DIR@", strings.Trim(string(escaped), `"`))
	var config map[string]any
	if err := json.Unmarshal([]byte(text), &config); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(raw), config
}

func vetText(t *testing.T, name, dir, access string) error {
	t.Helper()
	raw, config := fixture(t, name, dir)
	if err := CheckText(raw, access); err != nil {
		return err
	}
	return Vet(config, dir, access)
}

func appOf(config map[string]any) map[string]any {
	return config["services"].(map[string]any)["app"].(map[string]any)
}

const keepsData = "; a Contained stack keeps its data in named volumes"

func TestVetReadsTheNormalisedConfig(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ name, message string }{
		{"anchor", "service app mounts /etc from the server" + keepsData},
		{"merge-key", "service app shares the server's ipc"},
		{"extends", "extends is not allowed; paste a single compose file"},
		{"interpolation", "service app asks for privileged mode"},
		{"network-mode-host", "service app shares the server's network"},
		{"root-mount", "service app mounts / from the server" + keepsData},
		{"docker-socket", "service app mounts /var/run/docker.sock from the server" + keepsData},
		{"build", "service app builds from source; only ready images can run"},
		{"cap-add", "service app asks for extra capabilities"},
		{"pid-host", "service app shares the server's pid"},
		{"replicas", "service app asks for 2 copies; a Contained service runs one, so its limits hold"},
		{"registry", "service app pulls its image from 0.0.0.0, which is the server itself"},
		{"include", "include is not allowed; paste a single compose file"},
		{"dollar", "service app writes $ in pid; a Contained stack cannot use it there"},
	}
	for _, item := range cases {
		if err := vetText(t, item.name, dir, "contained"); err == nil || err.Error() != item.message {
			t.Errorf("%s contained: got %v, want %q", item.name, err, item.message)
		}
		err := vetText(t, item.name, dir, "full")
		if item.name == "build" {
			if err == nil || err.Error() != item.message {
				t.Errorf("build full: got %v", err)
			}
		} else if err != nil {
			t.Errorf("%s full: %v", item.name, err)
		}
	}
	if err := vetText(t, "plain", dir, "contained"); err != nil {
		t.Fatalf("a plain stack runs Contained: %v", err)
	}
	_, config := fixture(t, "plain", dir)
	appOf(config)["extends"] = map[string]any{"service": "base"}
	if err := Vet(config, dir, "contained"); err == nil || err.Error() != "service app uses extends; paste a single compose file" {
		t.Fatalf("extends left in the normalised file: %v", err)
	}
	for _, key := range []string{"image", "network_mode", "volumes", "ports", "logging", "sysctls"} {
		_, config := fixture(t, "plain", dir)
		appOf(config)[key] = []any{map[string]any{"x": "${HOST:-host}"}}
		if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), "writes $ in "+key) {
			t.Errorf("$ in %s: %v", key, err)
		}
	}
	_, config = fixture(t, "plain", dir)
	appOf(config)["annotations"] = map[string]any{"a": "b"}
	if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), "uses annotations") {
		t.Fatalf("annotations: %v", err)
	}
	if err := Vet(map[string]any{}, dir, "open"); err == nil {
		t.Fatal("an unknown access is refused")
	}
}

func TestAContainedStackIsFittedAfterVetting(t *testing.T) {
	dir := t.TempDir()
	_, config := fixture(t, "plain", dir)
	if err := Vet(config, dir, "contained"); err != nil {
		t.Fatal(err)
	}
	service := appOf(config)
	if service["cpus"] != float64(1) || service["mem_limit"] != float64(1<<30) || service["pids_limit"] != float64(512) {
		t.Fatalf("defaults: %#v", service)
	}
	if !slices.Contains(service["cap_drop"].([]any), any("NET_RAW")) {
		t.Fatalf("NET_RAW is dropped: %#v", service["cap_drop"])
	}
	network := config["networks"].(map[string]any)["default"].(map[string]any)
	bridge := network["driver_opts"].(map[string]any)["com.docker.network.bridge.name"].(string)
	if bridge != bridgeName("web", "default") || len(bridge) != 15 || !strings.HasPrefix(bridge, "krc") || network["enable_ipv6"] != false {
		t.Fatalf("network: %#v", network)
	}
	if err := Vet(config, dir, "contained"); err != nil {
		t.Fatalf("vetting the fitted file again passes: %v", err)
	}
	if dropped := service["cap_drop"].([]any); len(dropped) != 1 {
		t.Fatalf("NET_RAW is added once: %#v", dropped)
	}
	service["mem_limit"] = "4g"
	if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), "1 GB of memory") {
		t.Fatalf("more memory than a Contained stack gets: %v", err)
	}
	if err := Vet(config, dir, "full"); err != nil {
		t.Fatalf("Full access sets its own limits: %v", err)
	}
}

func TestAContainedStackKeepsToItsOwnNetworks(t *testing.T) {
	dir := t.TempDir()
	subnet := func(text string) map[string]any {
		return map[string]any{"name": "web_default", "ipam": map[string]any{"config": []any{map[string]any{"subnet": text}}}}
	}
	cases := []struct {
		key     string
		network map[string]any
		message string
	}{
		{"default", map[string]any{"name": "lan", "external": true}, "network default is external"},
		{"default", map[string]any{"name": "bridge"}, "network default is named bridge"},
		{"default", map[string]any{"name": "web_default", "driver": "macvlan"}, "macvlan driver"},
		{"default", map[string]any{"name": "web_default", "driver": "overlay"}, "bridge networks"},
		{"default", map[string]any{"name": "web_default", "driver_opts": map[string]any{"com.docker.network.bridge.name": "docker0"}}, "driver options"},
		{"default", map[string]any{"name": "web_default", "driver_opts": map[string]any{"com.docker.network.bridge.name": bridgeName("web", "default"), "com.docker.network.bridge.enable_icc": "true"}}, "driver options"},
		{"default", map[string]any{"name": "web_default", "enable_ipv6": true}, "IPv6"},
		{"my_net", map[string]any{"name": "web_my_net"}, "network my_net has _ in its name"},
		{"default", subnet("169.254.169.0/24"), "network default chooses its own addresses; a Contained stack lets Docker choose them"},
		{"default", subnet("172.30.0.0/24"), "chooses its own addresses"},
		{"default", map[string]any{"name": "web_default", "ipam": map[string]any{"driver": "default"}}, "chooses its own addresses"},
		{"default", map[string]any{"name": "web_default", "ipam": "none"}, "chooses its own addresses"},
	}
	for _, item := range cases {
		_, config := fixture(t, "plain", dir)
		config["networks"] = map[string]any{item.key: item.network}
		if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), item.message) {
			t.Errorf("%s %v: %v", item.key, item.network, err)
		}
	}
	full := []struct{ subnet, message string }{
		{"10.88.37.0/24", "network default uses 10.88.37.0/24, which overlaps the private network"},
		{"10.0.0.0/8", "overlaps the private network"},
		{"fd88::/16", "overlaps the private network"},
		{"wide", "not an address range"},
	}
	for _, item := range full {
		_, config := fixture(t, "plain", dir)
		config["networks"] = map[string]any{"default": subnet(item.subnet)}
		if err := Vet(config, dir, "full"); err == nil || !strings.Contains(err.Error(), item.message) {
			t.Errorf("Full %s: %v", item.subnet, err)
		}
	}
	_, config := fixture(t, "plain", dir)
	config["networks"] = map[string]any{"default": subnet("172.30.0.0/24")}
	if err := Vet(config, dir, "full"); err != nil {
		t.Fatalf("a Full subnet away from the private network: %v", err)
	}
	for _, field := range []string{"ipv4_address", "ipv6_address", "link_local_ips"} {
		_, config := fixture(t, "plain", dir)
		appOf(config)["networks"] = map[string]any{"default": map[string]any{field: "169.254.169.254"}}
		if err := Vet(config, dir, "contained"); err == nil || err.Error() != "service app chooses its own address on network default; a Contained stack lets Docker choose it" {
			t.Errorf("%s: %v", field, err)
		}
	}
	for _, networks := range []any{nil, map[string]any{}, []any{}, "default"} {
		_, config := fixture(t, "plain", dir)
		if networks == nil {
			delete(appOf(config), "networks")
		} else {
			appOf(config)["networks"] = networks
		}
		if err := Vet(config, dir, "contained"); err == nil || err.Error() != "service app is on no network; a Contained stack keeps every service on its own networks" {
			t.Errorf("networks %#v: %v", networks, err)
		}
	}
	for _, mode := range []string{"none", "service:db"} {
		_, config := fixture(t, "plain", dir)
		delete(appOf(config), "networks")
		appOf(config)["network_mode"] = mode
		if err := Vet(config, dir, "contained"); err != nil {
			t.Errorf("network_mode %s needs no network: %v", mode, err)
		}
	}
	_, config = fixture(t, "plain", dir)
	config["volumes"] = map[string]any{"my_data": map[string]any{"name": "web_my_data"}}
	if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), "volume my_data has _ in its name") {
		t.Fatalf("volume name: %v", err)
	}
}

func TestABindMountOutsideTheStackFolderIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	mount := func(access string, volume any) error {
		_, config := fixture(t, "plain", dir)
		appOf(config)["volumes"] = []any{volume}
		return Vet(config, dir, access)
	}
	for _, source := range []string{"/etc", filepath.Join(dir, ".."), dir + "-other", dir, filepath.Join(dir, "data"), "."} {
		bind := map[string]any{"type": "bind", "source": source, "target": "/x"}
		if err := mount("contained", bind); err == nil || err.Error() != "service app mounts "+source+" from the server"+keepsData {
			t.Errorf("%s: %v", source, err)
		}
		if err := mount("full", bind); err != nil {
			t.Errorf("Full keeps its binds: %s %v", source, err)
		}
	}
	for _, kind := range []string{"image", "npipe", "cluster", ""} {
		if err := mount("contained", map[string]any{"type": kind, "source": "x", "target": "/x"}); err == nil || !strings.Contains(err.Error(), keepsData) {
			t.Errorf("a %q volume: %v", kind, err)
		}
	}
	for _, kind := range []string{"volume", "tmpfs"} {
		if err := mount("contained", map[string]any{"type": kind, "source": "data", "target": "/x"}); err != nil {
			t.Errorf("a %s volume stays inside Docker: %v", kind, err)
		}
	}
	if err := mount("contained", "./data:/data"); err == nil || !strings.Contains(err.Error(), "did not resolve") {
		t.Errorf("a short volume: %v", err)
	}
	_, config := fixture(t, "plain", dir)
	appOf(config)["volumes"] = "./data:/data"
	if err := Vet(config, dir, "contained"); err == nil || !strings.Contains(err.Error(), "shape") {
		t.Errorf("volumes that are not a list: %v", err)
	}
	hostPaths := []struct {
		change  func(map[string]any)
		message string
	}{
		{func(c map[string]any) {
			c["secrets"] = map[string]any{"key": map[string]any{"file": filepath.Join(dir, "key")}}
		}, "secret key reads " + filepath.Join(dir, "key") + " from the server"},
		{func(c map[string]any) { c["configs"] = map[string]any{"key": map[string]any{"environment": "HOME"}} }, "config key reads HOME from the server's environment"},
		{func(c map[string]any) {
			appOf(c)["env_file"] = []any{map[string]any{"path": filepath.Join(dir, ".env"), "required": true}}
		}, "service app reads " + filepath.Join(dir, ".env") + " from the server"},
		{func(c map[string]any) { appOf(c)["label_file"] = []any{"/etc/shadow"} }, "service app reads /etc/shadow from the server"},
		{func(c map[string]any) { appOf(c)["env_file"] = "/etc/shadow" }, "service app reads /etc/shadow from the server"},
		{func(c map[string]any) { appOf(c)["env_file"] = map[string]any{"path": "/etc/shadow"} }, "service app reads /etc/shadow from the server"},
		{func(c map[string]any) { appOf(c)["env_file"] = []any{} }, "service app reads env_file from the server"},
		{func(c map[string]any) { appOf(c)["label_file"] = map[string]any{"x": "y"} }, "service app reads label_file from the server"},
		{func(c map[string]any) { appOf(c)["develop"] = map[string]any{"watch": []any{}} }, "service app uses develop, which a Contained stack does not allow; choose Full access to run it"},
		{func(c map[string]any) { appOf(c)["volumes_from"] = []any{"${OTHER:-container:x}"} }, "service app writes $ in volumes_from; a Contained stack cannot use it there"},
	}
	for _, item := range hostPaths {
		_, config := fixture(t, "plain", dir)
		item.change(config)
		if err := Vet(config, dir, "contained"); err == nil || err.Error() != item.message {
			t.Errorf("got %v, want %q", err, item.message)
		}
	}
	_, config = fixture(t, "plain", dir)
	config["configs"] = map[string]any{"key": map[string]any{"content": "inline"}}
	if err := Vet(config, dir, "contained"); err != nil {
		t.Errorf("a config written in the file reads nothing from the server: %v", err)
	}
}

func portsOf(t *testing.T, config map[string]any) []map[string]any {
	t.Helper()
	var ports []map[string]any
	for _, raw := range appOf(config)["ports"].([]any) {
		ports = append(ports, raw.(map[string]any))
	}
	return ports
}

func TestEveryPublishedPortIsBoundLocally(t *testing.T) {
	dir := t.TempDir()
	_, config := fixture(t, "ports", dir)
	if err := Bind(config, "", nil); err != nil {
		t.Fatal(err)
	}
	local := portsOf(t, config)
	if len(local) != 15 {
		t.Fatalf("one binding per published port: %d %#v", len(local), local)
	}
	for _, port := range local {
		if port["host_ip"] != "127.0.0.1" {
			t.Fatalf("published on more than the server itself: %#v", port)
		}
	}

	_, config = fixture(t, "ports", dir)
	if err := Bind(config, "10.88.37.2", []int{8080}); err != nil {
		t.Fatal(err)
	}
	ports := portsOf(t, config)
	var private []map[string]any
	for _, port := range ports {
		switch port["host_ip"] {
		case "127.0.0.1":
		case "10.88.37.2":
			private = append(private, port)
		default:
			t.Fatalf("host IP %#v", port)
		}
	}
	if len(ports) != 16 || len(private) != 1 || private[0]["published"] != "8080" || private[0]["target"] != float64(80) {
		t.Fatalf("only 8080 is added on kry0: %#v", ports)
	}
	if expose := appOf(config)["expose"]; !slices.Equal(expose.([]any), []any{"9000"}) {
		t.Fatalf("expose is left alone: %#v", expose)
	}
}

func TestADualStackPortBecomesOneLocalBinding(t *testing.T) {
	config := map[string]any{"services": map[string]any{"app": map[string]any{"ports": []any{
		map[string]any{"mode": "ingress", "host_ip": "0.0.0.0", "target": float64(80), "published": "8080", "protocol": "tcp"},
		map[string]any{"mode": "ingress", "host_ip": "::", "target": float64(80), "published": "8080", "protocol": "tcp"},
		map[string]any{"mode": "ingress", "host_ip": "", "target": float64(80), "protocol": "tcp"},
		map[string]any{"mode": "ingress", "target": float64(80), "published": "8100-8110", "protocol": "tcp"},
	}}}}
	if err := Bind(config, "10.88.37.2", []int{8105}); err != nil {
		t.Fatal(err)
	}
	ports := portsOf(t, config)
	if len(ports) != 4 {
		t.Fatalf("%#v", ports)
	}
	for _, port := range ports[:3] {
		if port["host_ip"] != "127.0.0.1" {
			t.Fatalf("%#v", port)
		}
	}
	if ports[3]["host_ip"] != "10.88.37.2" || ports[3]["published"] != "8105" {
		t.Fatalf("one port out of a range reaches kry0: %#v", ports[3])
	}
}

func TestAPortForTheNetworkNeedsTheServerInIt(t *testing.T) {
	dir := t.TempDir()
	_, config := fixture(t, "ports", dir)
	if err := Bind(config, "", []int{8080}); err == nil || err.Error() != "this server is not in the private network, so no port can be served to it" {
		t.Fatalf("got %v", err)
	}
	for _, own := range []string{"0.0.0.0", "::", "fd00::2", "127.0.0.1", "kry0"} {
		if err := Bind(config, own, []int{8080}); err == nil {
			t.Errorf("%s is not an address to serve on", own)
		}
	}
	for _, ports := range []any{[]any{"8080:80"}, "8080:80", map[string]any{"web": "8080:80"}} {
		config := map[string]any{"services": map[string]any{"app": map[string]any{"ports": ports}}}
		if err := Bind(config, "", nil); err == nil {
			t.Errorf("ports compose did not resolve are refused: %#v", ports)
		}
	}
}

func TestTheEnvFileIsPrivateAndNeverRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "compose", "web")
	env := "DB_PASSWORD=hunter2\nexport API_KEY='k'\n# NOTE=x\nAPI_KEY=again\nnot a line\n"
	command := trust.Command{Args: map[string]string{"compose": "services:\n  app:\n    image: nginx:1.27\n", "access": "contained", "network": "8080,443", "env": "sealed", "title": "Web", "names": "app=web-app"}}
	opened := ""
	unseal := func(sealed string) ([]byte, error) {
		opened = sealed
		return []byte(env), nil
	}
	if err := Write(dir, command, unseal); err != nil {
		t.Fatal(err)
	}
	if opened != "sealed" {
		t.Fatalf("unsealed %q", opened)
	}
	written, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil || string(written) != env {
		t.Fatalf("%q %v", written, err)
	}
	if info, err := os.Stat(filepath.Join(dir, ".env")); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("the .env is 0600: %v %v", info.Mode(), err)
	}
	compose, names, err := Read(dir)
	if err != nil || compose != command.Args["compose"] || !slices.Equal(names, []string{"API_KEY", "DB_PASSWORD"}) {
		t.Fatalf("%q %q %v", compose, names, err)
	}
	if strings.Contains(strings.Join(names, ""), "hunter2") {
		t.Fatal("a value left the server")
	}
	meta, err := ReadMeta(dir)
	if err != nil || meta.Access != "contained" || meta.Title != "Web" || meta.Names["app"] != "web-app" || !slices.Equal(meta.Network, []int{8080, 443}) {
		t.Fatalf("%#v %v", meta, err)
	}

	edit := trust.Command{Args: map[string]string{"compose": "services:\n  app:\n    image: nginx:1.28\n", "access": "full", "network": ""}}
	if err := Write(dir, edit, func(string) ([]byte, error) { t.Fatal("nothing to unseal"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if kept, _ := os.ReadFile(filepath.Join(dir, ".env")); string(kept) != env {
		t.Fatal("an edit without an .env keeps the one there")
	}
	meta, _ = ReadMeta(dir)
	if meta.Access != "full" || meta.Title != "Web" || meta.Names["app"] != "web-app" || len(meta.Network) != 0 {
		t.Fatalf("an edit keeps the title and names it does not send: %#v", meta)
	}

	for _, access := range []string{"", "open", "Contained"} {
		if err := Write(dir, trust.Command{Args: map[string]string{"compose": "x", "access": access, "network": ""}}, nil); err == nil {
			t.Errorf("access %q is refused", access)
		}
	}
	if err := Write(dir, trust.Command{Args: map[string]string{"compose": "x", "access": "full", "network": "", "env": "sealed"}}, func(string) ([]byte, error) {
		return []byte(strings.Repeat("A", 16<<10+1)), nil
	}); err == nil {
		t.Fatal("an .env over 16 KB is refused")
	}
	if err := Write(dir, trust.Command{Args: map[string]string{"compose": "x", "access": "full", "network": "", "env": "sealed"}}, func(string) ([]byte, error) {
		return nil, errors.New("not for this server")
	}); err == nil {
		t.Fatal("an .env that does not open is refused")
	}

	empty := filepath.Join(t.TempDir(), "plain")
	if err := Write(empty, edit, nil); err != nil {
		t.Fatal(err)
	}
	if _, names, err := Read(empty); err != nil || names == nil || len(names) != 0 {
		t.Fatalf("a stack without an .env has no names: %#v %v", names, err)
	}
}

func TestAnEnvLinkIsNeverFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("ROOT_ONLY=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".env")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(dir); err == nil {
		t.Fatal("a linked .env is not read")
	}
	command := trust.Command{Args: map[string]string{"compose": "services: {}\n", "access": "full", "network": "", "env": "sealed"}}
	if err := Write(dir, command, func(string) ([]byte, error) { return []byte("A=1\n"), nil }); err != nil {
		t.Fatal(err)
	}
	if kept, _ := os.ReadFile(outside); string(kept) != "ROOT_ONLY=1\n" {
		t.Fatal("writing the .env followed the link out of the folder")
	}
	if info, err := os.Lstat(filepath.Join(dir, ".env")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the link is replaced by the file: %v", err)
	}
}

func TestRawTextCannotHideAnotherFile(t *testing.T) {
	const (
		word      = "extends is not allowed; paste a single compose file"
		escape    = `the compose file uses \x, \u or \U escapes; write the characters themselves`
		joined    = `the compose file continues a line with \; write it on one line`
		tagged    = "the compose file uses a !! tag; write plain values"
		explicit  = "the compose file uses an explicit ? key; write keys plainly"
		control   = "the compose file holds control characters"
		breaks    = "the compose file breaks lines with something other than a newline"
		directive = "the compose file uses a % directive; write plain values"
		verbatim  = "the compose file uses a !< tag; write plain values"
		tag       = "the compose file uses a ! tag; only !reset and !override are allowed"
	)
	head := "services:\n  app:\n    image: nginx:1.27\n"
	slash := string(rune(92))
	cases := []struct{ text, message string }{
		{head + `    "` + slash + `x65xtends": {service: base}` + "\n", escape},
		{head + `    "` + slash + `u0065xtends": {service: base}` + "\n", escape},
		{head + `    "` + slash + `U00000065xtends": {service: base}` + "\n", escape},
		{head + "    !!str extends: {service: base}\n", word},
		{"services:\n  app:\n    image: !!str nginx:1.27\n", tagged},
		{head + "    ? extends\n    : {service: base}\n", word},
		{"services:\n  app:\n    ? image\n    : nginx:1.27\n", explicit},
		{"x-key: &key extends\n" + head + "    *key : {service: base}\n", word},
		{head + `    "ext\` + "\n" + `      ends": {service: base}` + "\n", joined},
		{head + `    "ext\` + "\r\n" + `      ends": {service: base}` + "\n", joined},
		{"include:\n  - other.yaml\n" + head, "include is not allowed; paste a single compose file"},
		{"{\"services\": {\"app\": {\"image\": \"nginx\", \"extends\": \"base\"}}}", word},
		{head + "    command: [\"e\x00xtends\"]\n", control},
		{"\ufeff" + head, control},
		{head + `    "ext\` + "\r" + `      ends": {service: base}` + "\n", breaks},
		{head + `    "ext\` + "\u0085" + `      ends": {service: base}` + "\n", breaks},
		{head + `    "ext\` + "\u2028" + `ends": {service: base}` + "\n", breaks},
		{head + `    "ext\` + "\u2029" + `ends": {service: base}` + "\n", breaks},
		{head + "    command: [echo]\r", breaks},
		{head + "    !<tag:yaml.org,2002:binary> ZXh0ZW5kcw==: {service: base}\n", verbatim},
		{"%TAG ! tag:yaml.org,2002:\n---\n" + head + "    !binary ZXh0ZW5kcw==: {service: base}\n", directive},
		{"  %YAML 1.2\n" + head, directive},
		{head + "    !binary ZXh0ZW5kcw==: {service: base}\n", tag},
		{head + "    labels: [!binary ZXh0ZW5kcw==]\n", tag},
		{head + "    labels: {a: !str x}\n", tag},
		{head + "    command: !resetx []\n", tag},
		{head + "    command: !reset.x []\n", tag},
		{head + "    command:\n      -!x y\n", tag},
		{head + "    command: [\"\xff\"]\n", "the compose file is not UTF-8"},
	}
	for _, item := range cases {
		if err := CheckText(item.text, "contained"); err == nil || err.Error() != item.message {
			t.Errorf("%q: got %v, want %q", item.text, err, item.message)
		}
		if err := CheckText(item.text, "full"); err != nil {
			t.Errorf("%q: Full reads it as it is: %v", item.text, err)
		}
	}
	for _, text := range []string{head, head + "    command: [echo, --includes, $$HOME]\n", head + "    labels: {note: \"a ? b\"}\n",
		head + "    environment: [PASS=pass!word]\n", head + "    command: !reset []\n", head + "    ports: !override [\"8080:80\"]\n",
		head + "    labels: {a: !reset null, b: 100%}\n", head + "    command: [echo]\r\n",
	} {
		if err := CheckText(text, "contained"); err != nil {
			t.Errorf("%q is plain: %v", text, err)
		}
	}
}
