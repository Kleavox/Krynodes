package actions

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
)

func (e Executor) lockNetwork() func() {
	file, err := os.OpenFile(filepath.Join(e.StateDir, networkLock), os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		log.Printf("network.json changes without its lock: %v", err)
		return func() {}
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		log.Printf("network.json changes without its lock: %v", err)
	}
	return func() { file.Close() }
}
