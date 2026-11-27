package service

import (
	"errors"
	"fmt"
	"io"
)

const (
	uninstalled = "Krynodes is removed from this laptop. It stays a member of the private network until you choose Remove from Network on the Network page.\n"
	atRestart   = "The program folder is removed when Windows restarts.\n"
)

type Remover interface {
	StopService() error
	DeleteService() error
	CloseTrays() error
	RemoveAdapter() error
	RemoveFirewall() error
	RemoveNRPT() error
	RemoveRunEntry() error
	RemoveShortcut() error
	RemoveData() error
	RemoveProgram() (bool, error)
}

func Uninstall(remover Remover, out io.Writer) error {
	later := false
	var failed []error
	for _, step := range []struct {
		what string
		do   func() error
	}{
		{"stop the service", remover.StopService},
		{"delete the service", remover.DeleteService},
		{"close the tray", remover.CloseTrays},
		{"remove the network adapter", remover.RemoveAdapter},
		{"remove the firewall rule", remover.RemoveFirewall},
		{"remove the exit's DNS rule", remover.RemoveNRPT},
		{"stop the tray starting with Windows", remover.RemoveRunEntry},
		{"remove the Start menu entry", remover.RemoveShortcut},
		{"remove the keys and the trust store", remover.RemoveData},
		{"remove the program", func() (err error) {
			later, err = remover.RemoveProgram()
			return err
		}},
	} {
		if err := step.do(); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", step.what, err))
		}
	}
	if len(failed) > 0 {
		return errors.Join(failed...)
	}
	done := uninstalled
	if later {
		done += atRestart
	}
	_, err := fmt.Fprint(out, done)
	return err
}
