//go:build windows

package bundle

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/Kleavox/krynodes/agent/windows/internal/store"
)

func Unpack(dir string) error {
	return unpack(files, dir, store.ProgramFolder, store.ProgramFile)
}

func Program() (string, error) {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(programs, "Krynodes", "krynodes.exe"), nil
}
