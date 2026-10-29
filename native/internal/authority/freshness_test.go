package authority

import (
	"encoding/json"
	"onecontrol/native/internal/contracts"
	"strings"
	"testing"
)

func TestFreshnessBoundaries(t *testing.T) {
	p := policy()
	raw, _ := json.Marshal(p)
	pe := signed(t, PolicyRole, "policy", raw, 32)
	for _, test := range []struct {
		name, want string
		change     func(*contracts.Freshness)
	}{
		{"nonce", "wrong_binding", func(f *contracts.Freshness) { f.Nonce = challenge(t).Nonce() }},
		{"digest", "wrong_binding", func(f *contracts.Freshness) { f.PolicyDigest = strings.Repeat("b", 64) }},
		{"device", "wrong_binding", func(f *contracts.Freshness) { f.DeviceID = "other" }},
		{"enrollment", "wrong_binding", func(f *contracts.Freshness) { f.EnrollmentID = "other" }},
		{"epoch", "stale_epoch", func(f *contracts.Freshness) { f.AuthorityEpoch = "8" }},
		{"expired", "expired", func(f *contracts.Freshness) { f.ExpiresAt = testNow }},
		{"future", "expired", func(f *contracts.Freshness) { f.IssuedAt = testNow + 1 }},
		{"unbounded lease", "expired", func(f *contracts.Freshness) { f.ExpiresAt = f.IssuedAt + 301 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := challenge(t)
			f := contracts.Freshness{SchemaVersion: 1, AuthorityEpoch: p.AuthorityEpoch, DeviceID: p.DeviceID, EnrollmentID: p.EnrollmentID, PolicyDigest: hash(raw), Nonce: c.Nonce(), IssuedAt: testNow - 1, ExpiresAt: testNow + 120}
			test.change(&f)
			fr, _ := json.Marshal(f)
			fe := signed(t, FreshnessRole, "fresh", fr, 32)
			if _, e := Accept(pe, fe, fixtureTrust(), binding(p), c, nil, testNow); e == nil || e.Error() != test.want {
				t.Fatalf("got %v want %s", e, test.want)
			}
		})
	}
}
func TestRootAuthorizedEpochTransition(t *testing.T) {
	p := policy()
	c := challenge(t)
	pe, fe := envelopes(t, p, c)
	first, e := Accept(pe, fe, fixtureTrust(), binding(p), c, nil, testNow)
	if e != nil {
		t.Fatal(e)
	}
	p.AuthorityEpoch = "8"
	p.Revision = "0"
	raw, _ := json.Marshal(p)
	c = challenge(t)
	f := contracts.Freshness{SchemaVersion: 1, AuthorityEpoch: "8", DeviceID: p.DeviceID, EnrollmentID: p.EnrollmentID, PolicyDigest: hash(raw), Nonce: c.Nonce(), IssuedAt: testNow, ExpiresAt: testNow + 120}
	fr, _ := json.Marshal(f)
	trust := fixtureTrust()
	trust.RootVersion = 2
	trust.Epoch = 8
	next, e := Accept(signed(t, PolicyRole, "policy", raw, 32, "2"), signed(t, FreshnessRole, "fresh", fr, 32, "2"), trust, binding(p), c, &first.Checkpoint, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if next.Checkpoint.AuthorityEpoch != "8" || next.Checkpoint.RootVersion != "2" || next.Checkpoint.Revision != "0" {
		t.Fatal(next.Checkpoint)
	}
}
func TestRoleKeysCannotReuseMaterial(t *testing.T) {
	tr := fixtureTrust()
	tr.Keys[1].Public = tr.Keys[0].Public
	if _, e := Verify(signed(t, PolicyRole, "policy", []byte("{}"), 32), PolicyRole, tr, testNow); e == nil || e.Error() != "untrusted_key" {
		t.Fatal(e)
	}
}
