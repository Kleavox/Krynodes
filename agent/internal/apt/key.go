package apt

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

type Key struct {
	Fingerprint string
	User        string
}

var errNotKey = errors.New("this is not an OpenPGP public key")

func dearmor(data []byte) ([]byte, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	_, after, found := strings.Cut(text, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
	if !found {
		return nil, errNotKey
	}
	body, _, found := strings.Cut(after, "-----END PGP PUBLIC KEY BLOCK-----")
	if !found {
		return nil, errNotKey
	}
	if _, rest, headers := strings.Cut(body, "\n\n"); headers {
		body = rest
	}
	var encoded strings.Builder
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "=") {
			break
		}
		encoded.WriteString(line)
	}
	return base64.StdEncoding.DecodeString(encoded.String())
}

func packet(data []byte) (tag byte, body, rest []byte, err error) {
	if len(data) < 2 || data[0]&0x80 == 0 {
		return 0, nil, nil, errNotKey
	}
	var length, header int
	if data[0]&0x40 != 0 {
		tag = data[0] & 0x3f
		switch first := int(data[1]); {
		case first < 192:
			length, header = first, 2
		case first < 224 && len(data) >= 3:
			length, header = (first-192)<<8+int(data[2])+192, 3
		case first == 255 && len(data) >= 6:
			length, header = int(binary.BigEndian.Uint32(data[2:6])), 6
		default:
			return 0, nil, nil, errNotKey
		}
	} else {
		tag = (data[0] >> 2) & 0x0f
		switch data[0] & 3 {
		case 0:
			length, header = int(data[1]), 2
		case 1:
			if len(data) < 3 {
				return 0, nil, nil, errNotKey
			}
			length, header = int(binary.BigEndian.Uint16(data[1:3])), 3
		case 2:
			if len(data) < 5 {
				return 0, nil, nil, errNotKey
			}
			length, header = int(binary.BigEndian.Uint32(data[1:5])), 5
		default:
			length, header = len(data)-1, 1
		}
	}
	if length < 0 || header+length > len(data) {
		return 0, nil, nil, errNotKey
	}
	return tag, data[header : header+length], data[header+length:], nil
}

func fingerprint(body []byte) (string, error) {
	if len(body) == 0 {
		return "", errNotKey
	}
	switch body[0] {
	case 4:
		sum := sha1.New()
		sum.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
		sum.Write(body)
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil))), nil
	case 5, 6:
		prefix := byte(0x9a)
		if body[0] == 6 {
			prefix = 0x9b
		}
		sum := sha256.New()
		sum.Write([]byte{prefix})
		sum.Write(binary.BigEndian.AppendUint32(nil, uint32(len(body))))
		sum.Write(body)
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil))), nil
	}
	return "", errors.New("this key's version is not one Krynodes reads")
}

func ReadKeys(data []byte) ([]Key, error) {
	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		decoded, err := dearmor(data)
		if err != nil {
			return nil, err
		}
		data = decoded
	}
	var keys []Key
	for len(data) > 0 {
		tag, body, rest, err := packet(data)
		if err != nil {
			return nil, err
		}
		data = rest
		switch tag {
		case 6:
			id, err := fingerprint(body)
			if err != nil {
				return nil, err
			}
			keys = append(keys, Key{Fingerprint: id})
		case 13:
			if len(keys) > 0 && keys[len(keys)-1].User == "" {
				keys[len(keys)-1].User = strings.ToValidUTF8(string(body), "")
			}
		}
	}
	if len(keys) == 0 {
		return nil, errNotKey
	}
	return keys, nil
}

func Short(fingerprint string) string {
	if len(fingerprint) < 16 {
		return fingerprint
	}
	tail := fingerprint[len(fingerprint)-16:]
	return tail[0:4] + " " + tail[4:8] + " " + tail[8:12] + " " + tail[12:16]
}
