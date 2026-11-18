package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestTwoUnitsChangingNetworkJSONAtOnceBothSurvive(t *testing.T) {
	executor, _ := newExecutor(t)
	if err := executor.saveNetwork(networkRecord{Joined: true}); err != nil {
		t.Fatal(err)
	}
	var inside atomic.Int32
	var group sync.WaitGroup
	for _, who := range []string{"198.51.100.1", "198.51.100.2"} {
		group.Go(func() {
			err := executor.updateNetwork(func(record *networkRecord) bool {
				if inside.Add(1) > 1 {
					t.Errorf("%s changed network.json while another change held it", who)
				}
				time.Sleep(100 * time.Millisecond)
				inside.Add(-1)
				record.Dropped = append(record.Dropped, who)
				return true
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	dropped := executor.readNetwork().Dropped
	slices.Sort(dropped)
	if !slices.Equal(dropped, []string{"198.51.100.1", "198.51.100.2"}) {
		t.Fatalf("one change was lost: %v", dropped)
	}
}

func TestNoInstallOrPurgeHoldsTheNetworkLock(t *testing.T) {
	install := "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools"
	purge := "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q wireguard-tools"
	for _, leave := range []string{"unprepare", "document"} {
		executor, run := networkExecutor(t)
		free := func(what string) func() {
			return func() {
				file, err := os.OpenFile(filepath.Join(executor.StateDir, networkLock), os.O_RDONLY|os.O_CREATE, 0o600)
				if err != nil {
					t.Error(err)
					return
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Errorf("%s while the network lock is held: %v", what, err)
				}
			}
		}
		os.Remove(executor.path("/usr/bin/wg"))
		run.effects = map[string]func(){install: free("installing " + networkTools), purge: free("purging " + networkTools + " (" + leave + ")")}
		keys := prepared(t, executor)
		rootFile(t, executor, "/usr/bin/wg", "")
		switch leave {
		case "unprepare":
			run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
			if result := hostRun(t, executor, networkRequest(t, idB, "unprepare", nil)); !result.OK {
				t.Fatalf("unprepare %+v", result)
			}
		case "document":
			peer, _ := peerKeys(t)
			if result := hostRun(t, executor, applyDocument(t, idB, twoMembers(t, executor, 1, keys, peer))); !result.OK {
				t.Fatalf("join %+v", result)
			}
			run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
			gone := twoMembers(t, executor, 2, keys, peer)
			gone.Members = gone.Members[:1]
			gone.Members[0].PSK = map[string]string{}
			if result := hostRun(t, executor, applyDocument(t, idC, gone)); !result.OK || result.Output != "left the private network" {
				t.Fatalf("leave %+v", result)
			}
		}
		if !slices.Contains(run.calls, install) || !slices.Contains(run.calls, purge) || executor.readNetwork().Tools {
			t.Fatalf("%s: the tools Krynodes added are installed and removed: %v", leave, run.calls)
		}
	}
}

func TestThePeriodicPathsWithNothingToWriteNeverWaitForTheLock(t *testing.T) {
	net, _, _ := newLaptopNet(t)
	net.apply(t, asIs)
	unlock := net.executor.lockNetwork()
	defer unlock()
	done := make(chan struct{})
	go func() {
		net.executor.retryRelayPorts(context.Background())
		net.executor.watchKnocks(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		unlock()
		<-done
		t.Fatal("a periodic path with nothing to write waited for the lock")
	}
}

func TestAServerBehindNATTakesTheLockOnlyToPutALaptopBack(t *testing.T) {
	net, run, _ := newLaptopNet(t)
	net.apply(t, behindNAT)
	hold := func(endpoint string) chan struct{} {
		run.respond["wg show kry0 dump"] = "cHJpdmF0ZQ==\tcHVibGlj\t51820\toff\n" + net.laptop.Public + "\t(none)\t" + endpoint + "\t10.88.0.9/32\t0\t0\t0\t25\n"
		done := make(chan struct{})
		go func() {
			net.executor.holdMeetings(context.Background())
			close(done)
		}()
		return done
	}
	unlock := net.executor.lockNetwork()
	select {
	case <-hold("203.0.113.21:51921"):
	case <-time.After(5 * time.Second):
		unlock()
		t.Fatal("an endpoint in place waited for the lock")
	}
	done := hold("203.0.113.23:51921")
	select {
	case <-done:
		unlock()
		t.Fatal("a laptop was put back without the lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	<-done
	if !slices.Contains(run.calls, "wg set kry0 peer "+net.laptop.Public+" endpoint 203.0.113.21:51921") {
		t.Fatalf("calls %q", run.calls)
	}
}
