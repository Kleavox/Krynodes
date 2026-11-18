package service

import (
	"errors"
	"fmt"
)

type Remover interface {
	StopService() error
	DeleteService() error
	CloseTrays() error
	RemoveAdapter() error
	RemoveFirewall() error
	RemoveNRPT() error
	RemoveRunEntry() error
	RemoveData() error
	RemoveProgram() error
}

func Uninstall(remover Remover) error {
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
		{"remove the keys and the trust store", remover.RemoveData},
		{"remove the program", remover.RemoveProgram},
	} {
		if err := step.do(); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", step.what, err))
		}
	}
	return errors.Join(failed...)
}
