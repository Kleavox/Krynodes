//go:build !linux

package stacks

import (
	"errors"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New(path+" is a link"))
	}
	return os.Open(path)
}
