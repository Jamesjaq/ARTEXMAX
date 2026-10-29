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
