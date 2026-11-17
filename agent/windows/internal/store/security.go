package store

const (
	administrators = "BA"
	localSystem    = "SY"
	systemSID      = "S-1-5-18"
	usersRead      = "0x1200a9"
)

func ownerFor(user string) string {
	if user == systemSID {
		return localSystem
	}
	return administrators
}

func descriptor(owner string, folder, readable bool) string {
	inherit := ""
	if folder {
		inherit = "OICI"
	}
	text := "O:" + owner + "D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)"
	if readable {
		text += "(A;" + inherit + ";" + usersRead + ";;;BU)"
	}
	return text
}

func trusted(owner string) bool {
	return owner == "S-1-5-32-544" || owner == systemSID
}
