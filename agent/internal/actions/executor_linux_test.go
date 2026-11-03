package actions

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAFifoRequestIsRefusedWithoutWaiting(t *testing.T) {
	executor, run := newExecutor(t)
	if err := syscall.Mkfifo(filepath.Join(executor.RequestDir, idA+".json"), 0o640); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- executor.Execute(context.Background()) }()
	select {
	case err := <-done:
		if err != nil || len(run.calls) != 0 || readResult(t, executor, idA).OK {
			t.Fatalf("err %v calls %#v", err, run.calls)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a FIFO must not stall the executor")
	}
}

func TestADirectorySwappedAfterItsCheckIsNotTrusted(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	before, err := os.Lstat(first)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(second)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if sameDirectory(before, root) {
		t.Fatal("a different directory must not pass")
	}
	own, err := os.OpenRoot(first)
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if !sameDirectory(before, own) {
		t.Fatal("the same directory must pass")
	}
}

func TestFilesTheRelayReadsAreWorldReadable(t *testing.T) {
	executor, _ := newExecutor(t)
	if err := executor.saveNetwork(networkRecord{Port: 51820}); err != nil {
		t.Fatal(err)
	}
	executor.event("port", "port:aa", map[string]string{"port": "80/tcp"})
	track := executor.track([]string{"admin", "restart"})
	track.enter("admin")
	track.end(true)
	for _, name := range []string{"network.json", eventsFile, setupFile} {
		info, err := os.Stat(filepath.Join(executor.StateDir, name))
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v %v; the relay reads it whoever wrote it", name, info, err)
		}
	}
}
