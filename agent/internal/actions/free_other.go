//go:build !linux

package actions

import (
	"errors"
	"os"
)

func freeBytes(string) (uint64, error) { return 0, errors.New("free space is only read on Linux") }

func owner(os.FileInfo) (int, int, bool) { return 0, 0, false }
