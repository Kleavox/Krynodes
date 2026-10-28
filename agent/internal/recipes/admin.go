package recipes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	adminName  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	adminLabel = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	adminTypes = map[string]string{
		"ssh-ed25519":                        "ED25519",
		"ecdsa-sha2-nistp256":                "ECDSA",
		"ecdsa-sha2-nistp384":                "ECDSA",
		"ecdsa-sha2-nistp521":                "ECDSA",
		"sk-ssh-ed25519@openssh.com":         "ED25519-SK",
		"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
		"ssh-rsa":                            "RSA",
	}
)

type AdminKey struct {
	Type, Blob, Label string
}

type AdminResult struct {
	Group    string
	KeyFiles []string
	Created  bool
}

type AdminSkipped string

func (s AdminSkipped) Error() string { return string(s) }

type Terminal interface {
	Ask(question string) (bool, bool)
	Passwd(ctx context.Context, name string) error
	Printf(format string, args ...any)
}

func ValidAdminName(name string) bool {
	return adminName.MatchString(name) && name != "root"
}

func ParseAdminKey(arg string) (AdminKey, error) {
	blob, label, ok := strings.Cut(arg, ":")
	raw, err := base64.StdEncoding.DecodeString(blob)
	if !ok || err != nil || !adminLabel.MatchString(label) || len(raw) < 4 {
		return AdminKey{}, fmt.Errorf("%.40s is not a key such as AAAA…:laptop", arg)
	}
	size := binary.BigEndian.Uint32(raw)
	if uint64(size)+4 > uint64(len(raw)) {
		return AdminKey{}, errors.New("a key's blob is cut short")
	}
	kind := string(raw[4 : 4+size])
	if _, known := adminTypes[kind]; !known {
		return AdminKey{}, errors.New("a key's type is not one Krynodes accepts")
	}
	return AdminKey{Type: kind, Blob: blob, Label: label}, nil
}

func (k AdminKey) Line() string {
	return k.Type + " " + k.Blob + " " + k.Label
}

func (k AdminKey) Fingerprint() string {
	raw, _ := base64.StdEncoding.DecodeString(k.Blob)
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func lookupUser(env Env, name string) (uid int, home string, found bool) {
	for _, line := range lines(env.path("/etc/passwd")) {
		if fields := strings.Split(line, ":"); len(fields) == 7 && fields[0] == name {
			uid, _ = strconv.Atoi(fields[2])
			return uid, fields[5], true
		}
	}
	return 0, "", false
}

func AddAdmin(ctx context.Context, env Env, name string, keys []AdminKey, tty Terminal) (AdminResult, error) {
	switch {
	case name == "root":
		return AdminResult{}, errors.New("root cannot be the admin user")
	case !adminName.MatchString(name):
		return AdminResult{}, fmt.Errorf("%.40s is not a user name such as musyaf", name)
	}
	uid, home, found := lookupUser(env, name)
	if found && uid < 1000 {
		return AdminResult{}, fmt.Errorf("%s is a system account on this server.", name)
	}
	tty.Printf("Admin user %s gets these SSH keys:\n", name)
	for _, key := range keys {
		tty.Printf("  %s %s %s\n", adminTypes[key.Type], key.Fingerprint(), key.Label)
	}
	yes, asked := tty.Ask("Add them? [y/N] ")
	switch {
	case !asked:
		return AdminResult{}, AdminSkipped("no terminal to type " + name + "'s password on")
	case !yes:
		return AdminResult{}, AdminSkipped("the keys were not confirmed")
	}
	result := AdminResult{Group: "sudo"}
	if Detect(env).Family == RHEL {
		result.Group = "wheel"
	}
	if !found {
		if err := env.run(ctx, "useradd", "-m", "-s", "/bin/bash", name); err != nil {
			return AdminResult{}, err
		}
		result.Created = true
		if _, home, found = lookupUser(env, name); !found {
			return AdminResult{}, fmt.Errorf("useradd did not make %s", name)
		}
	}
	if err := env.run(ctx, "usermod", "-aG", result.Group, name); err != nil {
		return AdminResult{}, err
	}
	directory := strings.TrimSuffix(home, "/") + "/.ssh"
	file := directory + "/authorized_keys"
	if err := os.MkdirAll(env.path(directory), 0o700); err != nil {
		return AdminResult{}, err
	}
	if err := os.Chmod(env.path(directory), 0o700); err != nil {
		return AdminResult{}, err
	}
	kept := slices.DeleteFunc(lines(env.path(file)), func(line string) bool { return strings.TrimSpace(line) == "" })
	for _, key := range keys {
		if !slices.ContainsFunc(kept, func(line string) bool { return slices.Contains(strings.Fields(line), key.Blob) }) {
			kept = append(kept, key.Line())
		}
	}
	if err := env.write(file, strings.Join(kept, "\n")+"\n", 0o600); err != nil {
		return AdminResult{}, err
	}
	if err := env.run(ctx, "chown", "-R", name+":", env.path(directory)); err != nil {
		return AdminResult{}, err
	}
	result.KeyFiles = []string{file}
	tty.Printf("Type a password for %s. It is for sudo and stays on this server.\n", name)
	set := false
	for range 3 {
		if tty.Passwd(ctx, name) == nil {
			set = true
			break
		}
	}
	if !set {
		return result, fmt.Errorf("the password was not set. Run sudo kry admin-user %s later.", name)
	}
	if output, err := env.output(ctx, "sudo", "-l", "-U", name); err != nil || !strings.Contains(output, "(ALL") {
		return result, errors.New("it is in the sudo group but sudo does not let it in. Check /etc/sudoers.")
	}
	return result, nil
}
