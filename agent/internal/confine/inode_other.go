//go:build !linux

package confine

import "os"

var fileID = func(os.FileInfo) uint64 { return 0 }
