package tray

import "strconv"

type notifyIconData struct {
	Size             uint32
	Wnd              uintptr
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             uintptr
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GuidItem         [16]byte
	BalloonIcon      uintptr
}

func shown(notes []string) string {
	switch len(notes) {
	case 0:
		return ""
	case 1:
		return notes[0]
	}
	return notes[len(notes)-1] + "\nAnd " + strconv.Itoa(len(notes)-1) + " more."
}
