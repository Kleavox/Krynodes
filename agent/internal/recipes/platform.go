package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Family string

const (
	Debian Family = "debian"
	RHEL   Family = "rhel"
)

var ErrUnsupported = errors.New("Protections and Docker setup support Debian, Ubuntu and RHEL-family servers")

type Platform struct {
	ID        string
	Version   string
	Codename  string
	Name      string
	Pretty    string
	Base      string
	Family    Family
	Verified  bool
	Checked   string
	EndOfLife time.Time
	Older     bool
}

var checkedVersions = map[string][2]string{
	"debian":    {"11", "13"},
	"ubuntu":    {"22.04", "26.04"},
	"rhel":      {"8", "10"},
	"rocky":     {"8", "10"},
	"almalinux": {"8", "10"},
	"ol":        {"8", "10"},
	"centos":    {"9", "10"},
	"fedora":    {"41", "44"},
}

var endOfLife = map[string]string{
	"debian 9": "2022-06-30", "debian 10": "2024-06-30", "debian 11": "2026-08-31", "debian 12": "2028-06-30", "debian 13": "2030-06-30",
	"ubuntu 16.04": "2021-04-30", "ubuntu 18.04": "2023-05-31", "ubuntu 20.04": "2025-05-31", "ubuntu 22.04": "2027-06-01",
	"ubuntu 23.10": "2024-07-12", "ubuntu 24.04": "2029-05-31", "ubuntu 24.10": "2025-07-10", "ubuntu 25.04": "2026-01-17",
	"ubuntu 25.10": "2026-07-01", "ubuntu 26.04": "2031-05-29",
	"rhel 8": "2029-05-31", "rhel 9": "2032-05-31", "rhel 10": "2035-05-31",
	"rocky 8": "2029-05-31", "rocky 9": "2032-05-31", "rocky 10": "2035-05-31",
	"almalinux 8": "2029-05-31", "almalinux 9": "2032-05-31", "almalinux 10": "2035-05-31",
	"ol 8": "2029-07-31", "ol 9": "2032-06-30", "ol 10": "2035-06-30",
	"centos 9": "2027-05-31", "centos 10": "2030-05-31",
	"fedora 41": "2025-12-15", "fedora 42": "2026-05-27", "fedora 43": "2026-12-09", "fedora 44": "2027-06-02",
}

func EndOfLifeFor(id, version string) (time.Time, bool) {
	stamp, known := endOfLife[id+" "+version]
	if !known {
		return time.Time{}, false
	}
	date, err := time.Parse(time.DateOnly, stamp)
	return date, err == nil
}

func Detect(env Env) Platform {
	values := map[string]string{}
	body, _ := os.ReadFile(env.path("/etc/os-release"))
	for line := range strings.SplitSeq(string(body), "\n") {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	id := strings.ToLower(values["ID"])
	like := strings.Fields(strings.ToLower(values["ID_LIKE"]))
	is := func(names ...string) bool {
		return slices.Contains(names, id) || slices.ContainsFunc(like, func(name string) bool { return slices.Contains(names, name) })
	}
	name := values["NAME"]
	if name == "" && id != "" {
		name = strings.ToUpper(id[:1]) + id[1:]
	}
	platform := Platform{ID: id, Version: values["VERSION_ID"], Pretty: values["PRETTY_NAME"], Name: strings.TrimSpace(name + " " + values["VERSION_ID"])}
	switch {
	case is("debian", "ubuntu"):
		platform.Family, platform.Base = Debian, "debian"
		platform.Codename = values["UBUNTU_CODENAME"]
		if id == "ubuntu" || platform.Codename != "" {
			platform.Base = "ubuntu"
		}
		if platform.Codename == "" {
			platform.Codename = values["VERSION_CODENAME"]
		}
	case is("rhel", "rocky", "almalinux", "centos", "ol", "fedora"):
		platform.Family, platform.Base = RHEL, "centos"
		if id == "rhel" || id == "fedora" {
			platform.Base = id
		}
		platform.Version, _, _ = strings.Cut(platform.Version, ".")
	}
	if span, known := checkedVersions[id]; known && platform.Family != "" && platform.Version != "" {
		platform.Checked = span[0] + " to " + span[1]
		platform.Older = compareVersions(platform.Version, span[0]) < 0
		platform.Verified = !platform.Older && compareVersions(platform.Version, span[1]) <= 0
	}
	platform.EndOfLife, _ = EndOfLifeFor(id, platform.Version)
	return platform
}

func (p Platform) Unverified() string {
	if p.Family == "" || p.Verified {
		return ""
	}
	if p.Checked == "" {
		return "Krynodes has not checked " + p.Name + "."
	}
	relation := "newer"
	if p.Older {
		relation = "older"
	}
	return fmt.Sprintf("%s %s is %s than the versions Krynodes has checked (%s).", p.Name[:strings.LastIndex(p.Name, " ")], p.Version, relation, p.Checked)
}

func compareVersions(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for index := range max(len(left), len(right)) {
		var x, y int
		if index < len(left) {
			x, _ = strconv.Atoi(left[index])
		}
		if index < len(right) {
			y, _ = strconv.Atoi(right[index])
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

func (e Env) apt(ctx context.Context, args ...string) error {
	return e.run(ctx, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=300"}, args...)...)
}

func (e Env) has(ctx context.Context, pkg string) bool {
	if Detect(e).Family == RHEL {
		_, err := e.output(ctx, "rpm", "-q", pkg)
		return err == nil
	}
	status, err := e.output(ctx, "dpkg-query", "-W", "-f", "${Status}", pkg)
	return err == nil && strings.Contains(status, "install ok installed")
}

func (e Env) install(ctx context.Context, packages ...string) (string, error) {
	var fresh []string
	for _, name := range packages {
		if !e.has(ctx, name) {
			fresh = append(fresh, name)
		}
	}
	if Detect(e).Family == RHEL {
		return strings.Join(fresh, " "), e.run(ctx, "dnf", append([]string{"install", "-y", "-q"}, packages...)...)
	}
	if err := e.apt(ctx, "update", "-q"); err != nil {
		return "", err
	}
	return strings.Join(fresh, " "), e.apt(ctx, append([]string{"install", "-y", "-q"}, packages...)...)
}

func (e Env) purge(ctx context.Context, packages ...string) error {
	if Detect(e).Family == RHEL {
		return e.run(ctx, "dnf", append([]string{"remove", "-y", "-q"}, packages...)...)
	}
	return e.apt(ctx, append([]string{"purge", "-y", "-q"}, packages...)...)
}
