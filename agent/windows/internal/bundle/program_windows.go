//go:build windows

package bundle

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func Program() (string, error) {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(programs, "Krynodes", "krynodes.exe"), nil
}
