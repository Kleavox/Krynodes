package store

import "testing"

func TestTheDescriptorNamesItsOwnerAndProtectsItsDACL(t *testing.T) {
	for _, c := range []struct {
		owner            string
		folder, readable bool
		want             string
	}{
		{administrators, true, false, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{administrators, false, false, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"},
		{localSystem, true, true, "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"},
		{localSystem, false, true, "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"},
	} {
		if got := descriptor(c.owner, c.folder, c.readable); got != c.want {
			t.Errorf("descriptor(%s, %v, %v) = %s, want %s", c.owner, c.folder, c.readable, got, c.want)
		}
	}
}

func TestTheServiceOwnsWhatItMakesAndInstallGivesItToAdministrators(t *testing.T) {
	if got := ownerFor("S-1-5-18"); got != localSystem {
		t.Errorf("the service's files are owned by %s", got)
	}
	for _, user := range []string{"S-1-5-21-1000-1000-1000-1001", "S-1-5-32-544", "S-1-5-19", ""} {
		if got := ownerFor(user); got != administrators {
			t.Errorf("a token of %q makes files owned by %s", user, got)
		}
	}
}

func TestOnlyAdministratorsAndSystemAreTrustedOwners(t *testing.T) {
	for owner, want := range map[string]bool{
		"S-1-5-32-544":                 true,
		"S-1-5-18":                     true,
		"S-1-5-21-1000-1000-1000-1001": false,
		"S-1-5-32-545":                 false,
		"S-1-5-32-5440":                false,
		"S-1-5-19":                     false,
		"S-1-5-20":                     false,
		"S-1-1-0":                      false,
		"S-1-3-0":                      false,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": false,
		"": false,
	} {
		if got := trusted(owner); got != want {
			t.Errorf("trusted(%q) = %v, want %v", owner, got, want)
		}
	}
}
