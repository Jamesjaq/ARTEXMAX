package agent

import "testing"

func testPassiveProfile() PassiveProfile {
	return PassiveProfile{Version: PassiveProfileVersion, ID: "headers-v1", Engine: "artex/passive", Checks: []PassiveCheck{{ID: "server", Method: "GET", URL: "https://example.test/", Headers: map[string]string{"Accept": "text/html"}, MaxBodyBytes: 4096, TimeoutMS: 5000}}}
}

func TestPassiveProfileSignAndVerify(t *testing.T) {
	p := testPassiveProfile()
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	p.Checks[0].URL = "https://example.test/changed"
	if err := p.Verify([]byte("secret")); err == nil {
		t.Fatal("mutated profile passed signature verification")
	}
}

func TestPassiveProfileRejectsActiveOrCredentialedChecks(t *testing.T) {
	p := testPassiveProfile()
	p.Checks[0].Method = "POST"
	if err := p.Validate(); err == nil {
		t.Fatal("POST passive check was accepted")
	}
	p = testPassiveProfile()
	p.Checks[0].Headers = map[string]string{"Authorization": "Bearer secret"}
	if err := p.Validate(); err == nil {
		t.Fatal("credential header was accepted")
	}
}

func TestPassiveRequestKeySeparatesAuthContexts(t *testing.T) {
	p := testPassiveProfile()
	first := PassiveRequestKey(p.Checks[0], "anonymous")
	second := PassiveRequestKey(p.Checks[0], "session:user-a")
	if first == second {
		t.Fatal("different auth contexts were deduplicated")
	}
	check := p.Checks[0]
	check.Headers = map[string]string{"accept": "text/html"}
	if first != PassiveRequestKey(check, "anonymous") {
		t.Fatal("header casing changed request identity")
	}
}
