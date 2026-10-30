package db

import (
	"testing"
)

func TestFindingIdentityStableAcrossPresentationChanges(t *testing.T) {
	first := FindingIdentity("xss", "artex/v1", "https://example.test/search", "  proof\nwith   spacing ", []int64{9, 2, 4})
	second := FindingIdentity(" XSS ", "artex/v1", "https://example.test/search", "proof with spacing", []int64{4, 9, 2})
	if first != second {
		t.Fatalf("identity changed across normalization: %s != %s", first, second)
	}
	if first == FindingIdentity("xss", "artex/v1", "https://example.test/search", "different proof", []int64{9, 2, 4}) {
		t.Fatal("different evidence produced the same identity")
	}
}

func TestRecordFindingPersistsStableIdentity(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("finding identity integration", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	first, err := store.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: "xss",
		Name: "first title", Severity: "high", Summary: "first summary", Evidence: "proof\nwith   spacing",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: " XSS ",
		Name: "changed title", Severity: "medium", Summary: "changed summary", Evidence: "proof with spacing",
	})
	if err != nil {
		t.Fatal(err)
	}
	var firstIdentity, secondIdentity string
	if err = d.QueryRow(`SELECT identity_key FROM findings WHERE id=$1`, first.FindingID).Scan(&firstIdentity); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT identity_key FROM findings WHERE id=$1`, second.FindingID).Scan(&secondIdentity); err != nil {
		t.Fatal(err)
	}
	want := FindingIdentity("xss", findingIdentityEngineVersion, "", "proof with spacing", nil)
	if firstIdentity != want || secondIdentity != want {
		t.Fatalf("production finding identities = %q and %q, want %q", firstIdentity, secondIdentity, want)
	}
}

func TestFindingLifecycleValidation(t *testing.T) {
	for _, state := range []string{
		FindingLifecycleIntroduced,
		FindingLifecyclePersistent,
		FindingLifecycleChanged,
		FindingLifecycleResolved,
		FindingLifecycleDismissed,
		FindingLifecycleNeedsVerification,
	} {
		if !validFindingLifecycle(state) {
			t.Errorf("state %q rejected", state)
		}
	}
	if validFindingLifecycle("confirmed") {
		t.Fatal("triage status was accepted as a lifecycle state")
	}
}
