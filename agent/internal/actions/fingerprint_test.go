package actions

import "testing"

func TestEveryServerRefusesATouchOnlyGrant(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.trust.RequireUV = false
	c.assertion.flags = flagPresent
	refused(t, c.verify(t, testNow), "was opened without a fingerprint, face or PIN")
}

func TestEveryServerRefusesATouchOnlyApproval(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.approvals[0].flags = flagPresent
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	refused(t, err, "was opened without a fingerprint, face or PIN")
}

func TestAPassphraseIsNeverAccepted(t *testing.T) {
	found := devices(t, "a")
	pass, _ := passphraseKey(t)
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["passphrase"] = pass
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "no longer use a passphrase")
}

func TestAStoredPassphraseIsDroppedAndFingerprintsAreReported(t *testing.T) {
	dir := t.TempDir()
	found := devices(t, "a")
	pass, _ := passphraseKey(t)
	stored := storeOf(found, []string{"a"}, []string{"a"})
	stored.Passphrase = &pass
	if err := SaveTrust(dir, stored); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Passphrase != nil || !loaded.RequireUV {
		t.Fatalf("loaded %+v", loaded)
	}
	if report := loaded.Report(); report.Passphrase || !report.RequireUV {
		t.Fatalf("report %+v", report)
	}
	next, err := apply(t, stored, newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a"))
	if err != nil || next.Passphrase != nil || !next.RequireUV {
		t.Fatalf("next %+v err %v", next, err)
	}
}
