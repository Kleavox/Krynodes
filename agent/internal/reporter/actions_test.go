package reporter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHeartbeatResponseCarriesActionsAndARefresh(t *testing.T) {
	var response HeartbeatResponse
	body := `{"ok":true,"intervalSeconds":60,"configVersion":"v1","refresh":true,"actions":[{"id":"0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01","kind":"docker","name":"adguard","action":"restart","expiresAt":"2026-09-29T10:10:00.000Z"}]}`
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.Refresh || len(response.Actions) != 1 || response.Actions[0].Name != "adguard" || response.Actions[0].Action != "restart" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAnActionsReportAndItsAnswerKeepTheirShape(t *testing.T) {
	code := 1
	empty := []ServiceEntry{}
	encoded, err := json.Marshal(ActionsReport{
		NodeID:    "n",
		Results:   []ActionResult{{ID: "r", OK: false, ExitCode: &code, Output: "Job failed", FinishedAt: "t"}},
		Inventory: &InventoryReport{Hash: "h", Services: &empty},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodeId":"n","results":[{"id":"r","ok":false,"exitCode":1,"output":"Job failed","finishedAt":"t"}],"inventory":{"hash":"h","services":[]}}`
	if string(encoded) != want {
		t.Fatalf("body\n got %s\nwant %s", encoded, want)
	}
	var response ActionsResponse
	if err := json.Unmarshal([]byte(`{"ok":true,"inventoryHash":"abc"}`), &response); err != nil {
		t.Fatal(err)
	}
	if response.InventoryHash == nil || *response.InventoryHash != "abc" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestAHashOnlyReportLeavesServicesOut(t *testing.T) {
	encoded, err := json.Marshal(ActionsReport{NodeID: "n", Inventory: &InventoryReport{Hash: "h"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"nodeId":"n","inventory":{"hash":"h"}}` {
		t.Fatalf("unexpected %s", encoded)
	}
}

func TestAnEmptyVaultIsSentAsNull(t *testing.T) {
	encoded, err := json.Marshal(InventoryReport{Hash: "h", Vault: &VaultSlot{}})
	if err != nil || !strings.Contains(string(encoded), `"vault":null`) {
		t.Fatalf("%s %v", encoded, err)
	}
	encoded, _ = json.Marshal(InventoryReport{Hash: "h"})
	if strings.Contains(string(encoded), "vault") {
		t.Fatalf("an unchanged inventory leaves the vault out: %s", encoded)
	}
}
