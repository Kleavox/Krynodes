package confine

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	SELinux  = "selinux"
	AppArmor = "apparmor"

	Enforcing  = "enforcing"
	Permissive = "permissive"
	Disabled   = "disabled"
	On         = "on"
	Off        = "off"
	KernelOff  = "kernel-off"

	SELinuxConfig = "/etc/selinux/config"
	Relabel       = "/.autorelabel"
	enforceFile   = "/sys/fs/selinux/enforce"
	enabledFile   = "/sys/module/apparmor/parameters/enabled"
	profilesFile  = "/sys/kernel/security/apparmor/profiles"
)

type State struct {
	System   string
	Mode     string
	Enforced int
	Complain int
	Config   string
	Restart  bool
}

func read(root, name string) (string, bool) {
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	return strings.TrimSpace(string(body)), err == nil
}

func ConfigMode(body string) string {
	for line := range strings.SplitSeq(body, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "SELINUX="); ok {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

func readSELinux(root string) State {
	state := State{System: SELinux, Mode: Disabled}
	config, _ := read(root, SELinuxConfig)
	state.Config = ConfigMode(config)
	switch enforce, _ := read(root, enforceFile); enforce {
	case "1":
		state.Mode = Enforcing
	case "0":
		state.Mode = Permissive
	}
	_, relabel := read(root, Relabel)
	state.Restart = relabel || (state.Mode == Disabled && (state.Config == Enforcing || state.Config == Permissive))
	return state
}

func readAppArmor(root string) State {
	state := State{System: AppArmor, Mode: KernelOff}
	if enabled, _ := read(root, enabledFile); enabled != "Y" {
		return state
	}
	profiles := Profiles(root)
	for _, mode := range profiles {
		switch mode {
		case "enforce":
			state.Enforced++
		case "complain":
			state.Complain++
		}
	}
	state.Mode = Off
	if len(profiles) > 0 {
		state.Mode = On
	}
	return state
}

func Read(root, family string) State {
	switch family {
	case "rhel":
		return readSELinux(root)
	case "debian":
		return readAppArmor(root)
	}
	if _, ok := read(root, enforceFile); ok {
		return readSELinux(root)
	}
	if enabled, _ := read(root, enabledFile); enabled == "Y" {
		return readAppArmor(root)
	}
	return State{}
}
