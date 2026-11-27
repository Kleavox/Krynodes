//go:build linux

package stacks

import (
	"context"
	"os"
	"syscall"
	"time"
)

func lockGuard(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(GuardLock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil
	}
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { file.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK {
			file.Close()
			return func() {}, nil
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
