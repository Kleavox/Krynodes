package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func krynodesStack(t *testing.T, executor Executor, name string) string {
	t.Helper()
	directory := filepath.Join(executor.StateDir, "compose", name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for file, body := range map[string]string{
		"compose.yaml":          "services:\n  app:\n    image: listmonk/listmonk\n",
		"compose.krynodes.json": `{"services":{"app":{"volumes":[{"source":"` + directory + `/data","target":"/data"}]}}}`,
		"krynodes.json":         `{"access":"contained"}`,
		"compose.previous.yaml": "old",
		".env":                  "DB_PASSWORD='s3cret'\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, file), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func TestUninstallTurnsProtectionsOffAndKeepsAppsRunning(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades", "on")
	if err := writeJSON(executor.StateDir, "recipes.json", recipeState{Applied: map[string]appliedRecipe{
		"security-updates": {At: executorNow, Saved: map[string]string{"installed": "unattended-upgrades"}},
	}}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(executor.StateDir, "lockdown.json", lockdownState{Containers: []string{"abc"}, At: executorNow}, 0o640); err != nil {
		t.Fatal(err)
	}
	old := krynodesStack(t, executor, "listmonk")

	removal := executor.Uninstall(context.Background(), false)

	kept := filepath.Join(filepath.Dir(executor.StateDir), "krynodes-stacks", "listmonk")
	compose, err := os.ReadFile(filepath.Join(kept, "compose.krynodes.json"))
	if err != nil || !strings.Contains(string(compose), kept+"/data") || strings.Contains(string(compose), old) {
		t.Fatalf("compose %s err %v", compose, err)
	}
	for _, gone := range []string{"krynodes.json", "compose.previous.yaml"} {
		if _, err := os.Stat(filepath.Join(kept, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(kept, ".env")); err != nil {
		t.Fatal("the app keeps its secrets")
	}
	if _, err := os.Stat(executor.StateDir); !os.IsNotExist(err) {
		t.Fatal("the state directory should be gone")
	}
	if _, err := os.Stat(executor.path("/etc/apt/apt.conf.d/52krynodes-auto-upgrades")); !os.IsNotExist(err) {
		t.Fatal("the protection should be undone")
	}
	for _, call := range []string{
		"docker start abc",
		"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q unattended-upgrades",
		"docker rm -f krynodes-tunnel",
		"docker image rm " + cloudflaredImage,
		"iptables -D DOCKER-USER -i " + guardBridges + " -d " + metadataAddress + " -j DROP",
	} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if len(removal.Problems) != 0 || !slices.Contains(removal.TurnedOff, "Automatic security updates are off") ||
		len(removal.Apps) != 1 || !strings.Contains(removal.Apps[0], kept) || !strings.Contains(removal.Apps[0], "compose.krynodes.json") {
		t.Fatalf("removal %#v", removal)
	}
}

func TestUninstallCanDeleteTheAppsWithTheirData(t *testing.T) {
	executor, run := securityExecutor(t)
	directory := krynodesStack(t, executor, "listmonk")
	run.respond["docker volume ls -q --filter label=com.docker.compose.project=listmonk"] = "listmonk_db\n"

	removal := executor.Uninstall(context.Background(), true)

	for _, call := range []string{
		"docker compose --project-name listmonk --project-directory " + directory + " -f " + filepath.Join(directory, "compose.krynodes.json") + " down -v --remove-orphans",
		"docker volume rm listmonk_db",
	} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(executor.StateDir), "krynodes-stacks", "listmonk")); !os.IsNotExist(err) {
		t.Fatal("nothing is kept")
	}
	if _, err := os.Stat(executor.StateDir); !os.IsNotExist(err) {
		t.Fatal("the state directory should be gone")
	}
	if len(removal.Problems) != 0 || !slices.Equal(removal.Apps, []string{"listmonk: deleted with its data"}) {
		t.Fatalf("removal %#v", removal)
	}
}

func TestUninstallKeepsAStackItCouldNotMove(t *testing.T) {
	executor, _ := securityExecutor(t)
	directory := krynodesStack(t, executor, "listmonk")
	if err := os.WriteFile(filepath.Join(filepath.Dir(executor.StateDir), "krynodes-stacks"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}

	removal := executor.Uninstall(context.Background(), false)

	if _, err := os.Stat(filepath.Join(directory, "compose.yaml")); err != nil {
		t.Fatal("a stack that could not move stays where it was")
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "trust.json")); !os.IsNotExist(err) {
		t.Fatal("everything else in the state directory goes")
	}
	if len(removal.Problems) != 1 || !strings.Contains(removal.Problems[0], directory) {
		t.Fatalf("removal %#v", removal)
	}
}

func TestUninstallSaysHowToRemoveTheDockerItInstalled(t *testing.T) {
	executor, _ := securityExecutor(t)
	if removal := executor.Uninstall(context.Background(), false); removal.Docker != "" {
		t.Fatalf("no word about a Docker Krynodes did not install: %#v", removal)
	}
	executor, _ = securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "NAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n")
	if err := writeJSON(executor.StateDir, "docker.json", dockerState{InstalledAt: executorNow}, 0o640); err != nil {
		t.Fatal(err)
	}
	removal := executor.Uninstall(context.Background(), false)
	if removal.Docker != "Docker stays for your apps. Krynodes installed it; remove it with: sudo dnf remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" {
		t.Fatalf("removal %#v", removal)
	}
	rootFile(t, executor, "/etc/docker/daemon.json", "{\"log-driver\": \"local\"}\n")
	if err := writeJSON(executor.StateDir, "docker.json", dockerState{InstalledAt: executorNow}, 0o640); err != nil {
		t.Fatal(err)
	}
	removal = executor.Uninstall(context.Background(), false)
	if !strings.HasSuffix(removal.Docker, " docker-compose-plugin && sudo rm /etc/docker/daemon.json") {
		t.Fatalf("the log setting Krynodes wrote goes with Docker: %#v", removal)
	}
}

func TestUninstallSaysWhenTheServerHeldAPieceOfTheToken(t *testing.T) {
	executor, _ := securityExecutor(t)
	if removal := executor.Uninstall(context.Background(), false); removal.Token != "" {
		t.Fatalf("no word about a token it never held: %#v", removal)
	}
	executor, _ = securityExecutor(t)
	if err := writeJSON(executor.StateDir, "vault.json", vaultFile{Set: "set-1", Holders: 3, Piece: []byte{1, 2}}, 0o600); err != nil {
		t.Fatal(err)
	}
	if removal := executor.Uninstall(context.Background(), false); !strings.Contains(removal.Token, "Cloudflare token") {
		t.Fatalf("removal %#v", removal)
	}
}
