package shamir

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAnyTwoPiecesRebuildTheSecretAndOneDoesNot(t *testing.T) {
	secret := []byte("cf-token-0123456789abcdefghijklmnopqrstuvwxyz")
	pieces, err := Split(secret, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(pieces) != 4 {
		t.Fatalf("%d pieces", len(pieces))
	}
	for i := range pieces {
		if len(pieces[i]) != len(secret)+1 || pieces[i][0] != byte(i+1) {
			t.Fatalf("piece %d: %x", i, pieces[i][:1])
		}
		if bytes.Contains(pieces[i], secret[:8]) {
			t.Fatalf("piece %d shows the secret", i)
		}
		for j := range pieces {
			if i == j {
				continue
			}
			got, err := Combine([][]byte{pieces[i], pieces[j]})
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("pieces %d and %d: %q %v", i, j, got, err)
			}
		}
	}
	if _, err := Combine(pieces[:1]); err == nil {
		t.Fatal("one piece must not be enough")
	}
	if _, err := Combine([][]byte{pieces[0], pieces[0]}); err == nil {
		t.Fatal("the same piece twice must be refused")
	}
	if _, err := Combine([][]byte{pieces[0], pieces[1][:5]}); err == nil {
		t.Fatal("pieces of different lengths must be refused")
	}
}

func TestOneHolderKeepsTheWholeSecret(t *testing.T) {
	pieces, err := Split([]byte("token"), 1)
	if err != nil || len(pieces) != 1 || pieces[0][0] != 0 {
		t.Fatalf("%x %v", pieces, err)
	}
	got, err := Combine(pieces)
	if err != nil || string(got) != "token" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Split(nil, 2); err == nil {
		t.Fatal("an empty secret must be refused")
	}
	if _, err := Split([]byte("x"), 256); err == nil {
		t.Fatal("at most 255 pieces")
	}
}

func TestTheAgentRebuildsWhatABrowserSplit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "shamir.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Secret string   `json:"secret"`
		Pieces []string `json:"pieces"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	decoded := make([][]byte, len(fixture.Pieces))
	for i, piece := range fixture.Pieces {
		if decoded[i], err = base64.RawURLEncoding.DecodeString(piece); err != nil {
			t.Fatal(err)
		}
	}
	for i := range decoded {
		for j := i + 1; j < len(decoded); j++ {
			got, err := Combine([][]byte{decoded[j], decoded[i]})
			if err != nil || string(got) != fixture.Secret {
				t.Fatalf("pieces %d and %d: %q %v", i, j, got, err)
			}
		}
	}
}
