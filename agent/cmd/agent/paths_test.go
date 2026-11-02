package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var joinedUnderRoot = regexp.MustCompile(`filepath\.Join\((?:\w+\.)?(?:Root|root), "[^/"]`)

func TestPathsUnderARootStartAtTheTopSoAnEmptyRootNeverMeansTheWorkingDirectory(t *testing.T) {
	var found []string
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for number, line := range strings.Split(string(body), "\n") {
			if joinedUnderRoot.MatchString(line) {
				found = append(found, fmt.Sprintf("%s:%d", filepath.ToSlash(path), number+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("with no root these are read from the working directory, which is /root under kry setup: %v", found)
	}
}
