package service

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type removerFake struct {
	done  []string
	fail  string
	later bool
}

func (f *removerFake) step(name string) error {
	f.done = append(f.done, name)
	if name == f.fail {
		return errors.New("access is denied")
	}
	return nil
}

func (f *removerFake) StopService() error    { return f.step("stop service") }
func (f *removerFake) DeleteService() error  { return f.step("delete service") }
func (f *removerFake) CloseTrays() error     { return f.step("close trays") }
func (f *removerFake) RemoveAdapter() error  { return f.step("adapter") }
func (f *removerFake) RemoveFirewall() error { return f.step("firewall") }
func (f *removerFake) RemoveNRPT() error     { return f.step("nrpt") }
func (f *removerFake) RemoveRunEntry() error { return f.step("run entry") }
func (f *removerFake) RemoveData() error     { return f.step("program data") }
func (f *removerFake) RemoveProgram() (bool, error) {
	return f.later, f.step("program files")
}

var everything = []string{"stop service", "delete service", "close trays", "adapter", "firewall", "nrpt", "run entry", "program data", "program files"}

func TestUninstallRemovesEverythingAndKeepsTheMembership(t *testing.T) {
	fake := &removerFake{}
	var out strings.Builder
	if err := Uninstall(fake, &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.done, everything) {
		t.Errorf("uninstall did %v, want %v", fake.done, everything)
	}
	if want := "Krynodes is removed from this laptop. It stays a member of the private network until you choose Remove from Network on the Network page.\n"; out.String() != want {
		t.Errorf("printed %q, want %q", out.String(), want)
	}
}

func TestUninstallSaysTheFolderGoesAtRestart(t *testing.T) {
	fake := &removerFake{later: true}
	var out strings.Builder
	if err := Uninstall(fake, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "The program folder is removed when Windows restarts.") || !strings.HasPrefix(out.String(), "Krynodes is removed from this laptop.") {
		t.Errorf("printed %q", out.String())
	}
}

func TestUninstallGoesOnPastAFailureAndSaysWhich(t *testing.T) {
	fake := &removerFake{fail: "firewall"}
	var out strings.Builder
	err := Uninstall(fake, &out)
	if err == nil || !strings.Contains(err.Error(), "remove the firewall rule: access is denied") {
		t.Errorf("Uninstall = %v, want the firewall step named", err)
	}
	if !slices.Equal(fake.done, everything) {
		t.Errorf("uninstall did %v, want every step", fake.done)
	}
	if out.Len() != 0 {
		t.Errorf("a failed uninstall said %q", out.String())
	}
}
