//go:build linux

package metrics

import "testing"

func TestDiskUsageCountsOnlyOccupiedBlocks(t *testing.T) {
	const blockSize = 4096
	const blocks = 263939740 // about 1.08 TB, the size of a WSL root volume
	const free = 263156506   // what the filesystem reports as free

	used, total := diskUsage(blocks, free, blockSize)

	if total != blocks*blockSize {
		t.Fatalf("total = %d, want %d", total, blocks*blockSize)
	}
	if want := int64((blocks - free) * blockSize); used != want {
		t.Fatalf("used = %d, want %d", used, want)
	}
}

func TestDiskUsageIgnoresTheRootReservation(t *testing.T) {
	const blockSize = 4096
	const blocks = 1000000
	const free = 950000
	const available = 900000 // 5% of the volume is held back for root

	used, _ := diskUsage(blocks, free, blockSize)

	reservedAsUsed := int64((blocks - available) * blockSize)
	if used == reservedAsUsed {
		t.Fatal("used counted the root reservation, which df does not")
	}
	if want := int64((blocks - free) * blockSize); used != want {
		t.Fatalf("used = %d, want %d", used, want)
	}
}

func TestDiskUsageOnAnEmptyVolume(t *testing.T) {
	used, total := diskUsage(1000, 1000, 4096)
	if used != 0 {
		t.Fatalf("used = %d on an empty volume, want 0", used)
	}
	if total != 4096000 {
		t.Fatalf("total = %d, want 4096000", total)
	}
}

func TestTheFullestDiskIsReported(t *testing.T) {
	sizes := map[string][2]int64{"/": {40, 100}, "/var/lib/docker": {97, 100}}
	read := func(path string) (int64, int64, error) {
		size, ok := sizes[path]
		if !ok {
			return 0, 0, errNoDisk
		}
		return size[0], size[1], nil
	}
	if used, total, err := fullest([]string{"/", "/var/lib/docker"}, read); err != nil || used != 97 || total != 100 {
		t.Fatalf("used %d total %d err %v", used, total, err)
	}
	if used, total, err := fullest([]string{"/", "/missing"}, read); err != nil || used != 40 || total != 100 {
		t.Fatalf("a path that is not there is skipped: %d %d %v", used, total, err)
	}
	if _, _, err := fullest([]string{"/missing"}, read); err == nil {
		t.Fatal("no disk at all is an error")
	}
}

func TestDockerMovedElsewhereIsMeasuredToo(t *testing.T) {
	if paths := diskPaths([]byte(`{"data-root": "/mnt/docker", "log-driver": "local"}`)); len(paths) != 3 || paths[2] != "/mnt/docker" {
		t.Fatalf("paths %q", paths)
	}
	if paths := diskPaths(nil); len(paths) != 2 {
		t.Fatalf("without daemon.json: %q", paths)
	}
	if paths := diskPaths([]byte("not json")); len(paths) != 2 {
		t.Fatalf("an unreadable daemon.json: %q", paths)
	}
}
