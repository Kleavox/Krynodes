package service

import (
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestZZDumpBody(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	if err := server.install(t.TempDir(), memory{}, newSystem(t), io.Discard); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(server.body)
	os.WriteFile(`C:\Users\j5mus\AppData\Local\Temp\kry-body.json`, data, 0o644)
}
