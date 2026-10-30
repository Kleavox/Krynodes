package confine

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	Denied = "denied"
	Status = "status"
	Policy = "policy"

	AuditLog = "/var/log/audit/audit.log"
	readMax  = 1 << 20
)

var (
	auditStamp = regexp.MustCompile(`audit\((\d+)\.\d+:\d+\)`)
	auditField = regexp.MustCompile(`([a-z_-]+)=("[^"]*"|\S+)`)
	avcDenied  = regexp.MustCompile(`avc:\s+denied\s+\{\s*([^}]*?)\s*\}`)
)

type Denial struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	System    string    `json:"system"`
	Program   string    `json:"program"`
	Pid       int       `json:"pid"`
	Wanted    string    `json:"wanted"`
	Type      string    `json:"type"`
	Level     string    `json:"level"`
	Enforcing string    `json:"enforcing,omitempty"`
}

type Cursor struct {
	Started bool   `json:"started"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
}

func Parse(text string) []Denial {
	found := []Denial{}
	for line := range strings.SplitSeq(text, "\n") {
		if denial, ok := parseLine(line); ok {
			found = append(found, denial)
		}
	}
	return found
}

func parseLine(line string) (Denial, bool) {
	fields := map[string]string{}
	for _, match := range auditField.FindAllStringSubmatch(line, -1) {
		if _, seen := fields[match[1]]; !seen {
			fields[match[1]] = strings.Trim(match[2], `"`)
		}
	}
	denial := Denial{Program: fields["comm"]}
	denial.Pid, _ = strconv.Atoi(fields["pid"])
	if match := auditStamp.FindStringSubmatch(line); match != nil {
		seconds, _ := strconv.ParseInt(match[1], 10, 64)
		denial.At = time.Unix(seconds, 0)
	}
	avc := avcDenied.FindStringSubmatch(line)
	switch {
	case fields["apparmor"] == "DENIED":
		denial.Kind, denial.System, denial.Type = Denied, AppArmor, fields["profile"]
		denial.Wanted = strings.TrimSpace(fields["operation"] + " " + fields["name"])
	case avc != nil:
		denial.Kind, denial.System = Denied, SELinux
		if parts := strings.SplitN(fields["scontext"], ":", 4); len(parts) == 4 {
			denial.Type, denial.Level = parts[2], parts[3]
		}
		target := fields["path"]
		if target == "" {
			target = fields["name"]
		}
		if target == "" && fields["src"] != "" {
			target = fields["src"] + "/" + strings.TrimSuffix(fields["tclass"], "_socket")
		}
		denial.Wanted = strings.TrimSpace(avc[1] + " " + target)
	case strings.Contains(line, "type=MAC_STATUS") || strings.Contains(line, "type=1404"):
		denial.Kind, denial.System, denial.Enforcing = Status, SELinux, fields["enforcing"]
	case strings.Contains(line, "type=MAC_POLICY_LOAD") || strings.Contains(line, "type=1403"):
		denial.Kind, denial.System = Policy, SELinux
	default:
		return Denial{}, false
	}
	denial.Program, denial.Type, denial.Wanted = clip(denial.Program, 64), clip(denial.Type, 200), clip(denial.Wanted, 200)
	return denial, true
}

func clip(text string, most int) string {
	if len(text) > most {
		return text[:most]
	}
	return text
}

func wholeLines(file *os.File, size, offset int64) (string, int64, error) {
	start := max(offset, size-readMax)
	body := make([]byte, size-start)
	read, err := file.ReadAt(body, start)
	body = body[:read]
	whole := bytes.LastIndexByte(body, '\n') + 1
	if read == 0 && err != nil {
		return "", offset, err
	}
	return string(body[:whole]), start + int64(whole), nil
}

func ReadNew(root string, cursor *Cursor) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(AuditLog))
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	inode := fileID(info)
	if !cursor.Started {
		*cursor = Cursor{Started: true, Inode: inode, Offset: info.Size()}
		return "", nil
	}
	rotated := ""
	if inode != cursor.Inode || info.Size() < cursor.Offset {
		if old, err := os.Open(path + ".1"); err == nil {
			if oldInfo, err := old.Stat(); err == nil && inode != cursor.Inode && fileID(oldInfo) == cursor.Inode {
				rotated, _, _ = wholeLines(old, oldInfo.Size(), cursor.Offset)
			}
			old.Close()
		}
		cursor.Inode, cursor.Offset = inode, 0
	}
	text, offset, err := wholeLines(file, info.Size(), cursor.Offset)
	cursor.Offset = offset
	return rotated + text, err
}

func Profiles(root string) map[string]string {
	profiles := map[string]string{}
	body, _ := read(root, profilesFile)
	for line := range strings.SplitSeq(body, "\n") {
		if at := strings.LastIndex(line, " ("); at > 0 && strings.HasSuffix(line, ")") {
			profiles[line[:at]] = line[at+2 : len(line)-1]
		}
	}
	return profiles
}
