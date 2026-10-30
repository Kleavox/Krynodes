package confine

import (
	"os"
	"path/filepath"
	"testing"
)

func file(t *testing.T, root, name, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSELinux(t *testing.T) {
	cases := []struct {
		name    string
		enforce string
		config  string
		want    State
	}{
		{"enforcing", "1", "SELINUX=enforcing\n", State{System: SELinux, Mode: Enforcing, Config: "enforcing"}},
		{"permissive", "0", "# comment\nSELINUX=permissive\nSELINUXTYPE=targeted\n", State{System: SELinux, Mode: Permissive, Config: "permissive"}},
		{"disabled", "", "SELINUX=disabled\n", State{System: SELinux, Mode: Disabled, Config: "disabled"}},
		{"disabled until a restart", "", "SELINUX=enforcing\n", State{System: SELinux, Mode: Disabled, Config: "enforcing", Restart: true}},
		{"no config", "", "", State{System: SELinux, Mode: Disabled}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.enforce != "" {
				file(t, root, "/sys/fs/selinux/enforce", c.enforce)
			}
			if c.config != "" {
				file(t, root, "/etc/selinux/config", c.config)
			}
			if got := Read(root, "rhel"); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestARelabelWaitingNeedsARestart(t *testing.T) {
	root := t.TempDir()
	file(t, root, "/sys/fs/selinux/enforce", "1")
	file(t, root, "/etc/selinux/config", "SELINUX=enforcing\n")
	file(t, root, "/.autorelabel", "")
	if got := Read(root, "rhel"); !got.Restart {
		t.Fatalf("got %+v", got)
	}
}

func TestReadAppArmor(t *testing.T) {
	profiles := "/usr/sbin/cupsd (enforce)\ndocker-default (enforce)\n/usr/bin/man (complain)\nunprivileged_userns (unconfined)\n"
	cases := []struct {
		name     string
		enabled  string
		profiles string
		want     State
	}{
		{"on", "Y\n", profiles, State{System: AppArmor, Mode: On, Enforced: 2, Complain: 1}},
		{"enabled, nothing loaded", "Y\n", "", State{System: AppArmor, Mode: Off}},
		{"off at boot", "N\n", "", State{System: AppArmor, Mode: KernelOff}},
		{"not in the kernel", "", "", State{System: AppArmor, Mode: KernelOff}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.enabled != "" {
				file(t, root, "/sys/module/apparmor/parameters/enabled", c.enabled)
			}
			if c.profiles != "" {
				file(t, root, "/sys/kernel/security/apparmor/profiles", c.profiles)
			}
			if got := Read(root, "debian"); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestOneSystemPerFamily(t *testing.T) {
	root := t.TempDir()
	file(t, root, "/sys/module/apparmor/parameters/enabled", "Y\n")
	if got := Read(root, "rhel"); got.System != SELinux {
		t.Fatalf("RHEL read as %+v", got)
	}
	file(t, root, "/sys/fs/selinux/enforce", "1")
	if got := Read(root, "debian"); got.System != AppArmor {
		t.Fatalf("Debian read as %+v", got)
	}
}

func TestAnUnknownSystemReadsWhatRuns(t *testing.T) {
	if got := Read(t.TempDir(), ""); got != (State{}) {
		t.Fatalf("got %+v", got)
	}
	root := t.TempDir()
	file(t, root, "/sys/fs/selinux/enforce", "0")
	if got := Read(root, ""); got.System != SELinux || got.Mode != Permissive {
		t.Fatalf("got %+v", got)
	}
	root = t.TempDir()
	file(t, root, "/sys/module/apparmor/parameters/enabled", "Y\n")
	file(t, root, "/sys/kernel/security/apparmor/profiles", "a (enforce)\n")
	if got := Read(root, ""); got.System != AppArmor || got.Enforced != 1 {
		t.Fatalf("got %+v", got)
	}
}
