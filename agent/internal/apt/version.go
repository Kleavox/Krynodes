package apt

import (
	"cmp"
	"strconv"
	"strings"
)

func order(char byte) int {
	switch {
	case char >= '0' && char <= '9':
		return 0
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
		return int(char)
	case char == '~':
		return -1
	}
	return int(char) + 256
}

func digit(char byte) bool {
	return char >= '0' && char <= '9'
}

func compareParts(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !digit(a[0])) || (b != "" && !digit(b[0])) {
			left, right := 0, 0
			if a != "" {
				left = order(a[0])
			}
			if b != "" {
				right = order(b[0])
			}
			if left != right {
				return cmp.Compare(left, right)
			}
			a, b = a[1:], b[1:]
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		first := 0
		for a != "" && b != "" && digit(a[0]) && digit(b[0]) {
			if first == 0 {
				first = cmp.Compare(a[0], b[0])
			}
			a, b = a[1:], b[1:]
		}
		if a != "" && digit(a[0]) {
			return 1
		}
		if b != "" && digit(b[0]) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}

func splitVersion(version string) (int, string, string) {
	epoch := 0
	if before, after, found := strings.Cut(version, ":"); found {
		if number, err := strconv.Atoi(before); err == nil {
			epoch, version = number, after
		}
	}
	revision := ""
	if dash := strings.LastIndex(version, "-"); dash >= 0 {
		version, revision = version[:dash], version[dash+1:]
	}
	return epoch, version, revision
}

func Compare(a, b string) int {
	epochA, upstreamA, revisionA := splitVersion(a)
	epochB, upstreamB, revisionB := splitVersion(b)
	return cmp.Or(cmp.Compare(epochA, epochB), compareParts(upstreamA, upstreamB), compareParts(revisionA, revisionB))
}
