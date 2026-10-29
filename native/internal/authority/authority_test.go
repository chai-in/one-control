package authority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"onecontrol/native/internal/contracts"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testNow int64 = 1800000000

var private *rsa.PrivateKey
var freshPrivate *rsa.PrivateKey

func TestMain(m *testing.M) {
	var e error
	private, e = rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		panic(e)
	}
	freshPrivate, e = rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		panic(e)
	}
	os.Exit(m.Run())
}
func fixtureTrust() Trust {
	return Trust{RootVersion: 1, Epoch: 7, Keys: []Key{{ID: "policy", Role: PolicyRole, Public: &private.PublicKey, NotBefore: testNow - 10, NotAfter: testNow + 10000}, {ID: "fresh", Role: FreshnessRole, Public: &freshPrivate.PublicKey, NotBefore: testNow - 10, NotAfter: testNow + 10000}}}
}
func signed(t *testing.T, role, key string, payload []byte, salt int, rootVersions ...string) []byte {
	t.Helper()
	rootVersion := "1"
	if len(rootVersions) > 0 {
		rootVersion = rootVersions[0]
	}
	protected, _ := json.Marshal(contracts.Protected{SchemaVersion: 1, Domain: role, Alg: "PS256", RootVersion: rootVersion, KeyID: key})
	digest := sha256.Sum256(SigningBytes(key, protected, payload))
	signingKey := private
	if key == "fresh" {
		signingKey = freshPrivate
	}
	sig, e := rsa.SignPSS(rand.Reader, signingKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: salt})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(contracts.Envelope{Protected: base64.RawURLEncoding.EncodeToString(protected), Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(sig)})
	return b
}
func policy() contracts.Policy {
	return contracts.Policy{SchemaVersion: 1, AuthorityEpoch: "7", Revision: "12", DeviceID: "device-1", EnrollmentID: "enrollment-1", Platform: "win-x64", Scope: contracts.Scope{Kind: "machine", MachineID: "machine-1"}, CatalogDigest: strings.Repeat("a", 64), Enabled: map[string]string{}, Disabled: []string{}, AllowedPermissions: []string{}, IssuedAt: testNow - 1, ExpiresAt: testNow + 1000}
}
func binding(p contracts.Policy) Binding {
	return Binding{p.DeviceID, p.EnrollmentID, p.Platform, p.Scope}
}
func envelopes(t *testing.T, p contracts.Policy, c *Challenge) ([]byte, []byte) {
	raw, _ := json.Marshal(p)
	f := contracts.Freshness{SchemaVersion: 1, AuthorityEpoch: p.AuthorityEpoch, DeviceID: p.DeviceID, EnrollmentID: p.EnrollmentID, PolicyDigest: hash(raw), Nonce: c.Nonce(), IssuedAt: testNow - 1, ExpiresAt: testNow + 120}
	fr, _ := json.Marshal(f)
	return signed(t, PolicyRole, "policy", raw, 32), signed(t, FreshnessRole, "fresh", fr, 32)
}
func challenge(t *testing.T) *Challenge {
	t.Helper()
	c, e := NewChallenge()
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestImmutablePolicyAndFreshChallenge(t *testing.T) {
	p := policy()
	c := challenge(t)
	pe, fe := envelopes(t, p, c)
	first, e := Accept(pe, fe, fixtureTrust(), binding(p), c, nil, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Accept(pe, fe, fixtureTrust(), binding(p), c, &first.Checkpoint, testNow); e == nil || e.Error() != "replayed_challenge" {
		t.Fatal("challenge replay", e)
	}
	next := challenge(t)
	pe, fe = envelopes(t, p, next)
	second, e := Accept(pe, fe, fixtureTrust(), binding(p), next, &first.Checkpoint, testNow+1)
	if e != nil {
		t.Fatal(e)
	}
	if second.Checkpoint.PolicyDigest != first.Checkpoint.PolicyDigest {
		t.Fatal("freshness changed policy identity")
	}
	p.Enabled["files"] = "1.0.0"
	c = challenge(t)
	pe, fe = envelopes(t, p, c)
	if _, e = Accept(pe, fe, fixtureTrust(), binding(p), c, &second.Checkpoint, testNow+1); e == nil || e.Error() != "equivocation" {
		t.Fatal("same revision changed bytes", e)
	}
}
func TestPolicyBoundaries(t *testing.T) {
	base := policy()
	c := challenge(t)
	pe, fe := envelopes(t, base, c)
	first, e := Accept(pe, fe, fixtureTrust(), binding(base), c, nil, testNow)
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name, want string
		change     func(*contracts.Policy, *Binding, *Trust, *int64)
	}{
		{"device", "wrong_binding", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { b.DeviceID = "other" }},
		{"enrollment", "wrong_binding", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { b.EnrollmentID = "other" }},
		{"platform", "wrong_binding", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { b.Platform = "linux-x64" }},
		{"machine", "wrong_binding", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { b.Scope.MachineID = "other" }},
		{"expired", "expired", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { p.ExpiresAt = testNow }},
		{"clock rollback", "clock_rollback", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { *n = testNow - 1 }},
		{"stale revision", "stale_revision", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { p.Revision = "11" }},
		{"epoch not root authorized", "stale_epoch", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { p.AuthorityEpoch = "8" }},
		{"epoch without root advance", "stale_epoch", func(p *contracts.Policy, b *Binding, tr *Trust, n *int64) { p.AuthorityEpoch = "8"; tr.Epoch = 8 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := policy()
			b := binding(p)
			tr := fixtureTrust()
			now := testNow
			test.change(&p, &b, &tr, &now)
			c := challenge(t)
			pe, fe := envelopes(t, p, c)
			_, e := Accept(pe, fe, tr, b, c, &first.Checkpoint, now)
			if e == nil || e.Error() != test.want {
				t.Fatalf("got %v want %s", e, test.want)
			}
		})
	}
}
func TestUserSessionBinding(t *testing.T) {
	p := policy()
	principal, session := "user-sid", "session-4"
	inc, local := challenge(t).Nonce(), challenge(t).Nonce()
	p.Scope = contracts.Scope{Kind: "user", MachineID: "machine-1", Principal: &principal, SessionID: &session, SessionIncarnation: &inc, LocalNonce: &local}
	for _, field := range []string{"principal", "session", "incarnation", "local"} {
		t.Run(field, func(t *testing.T) {
			b := binding(p)
			other := "other"
			switch field {
			case "principal":
				b.Scope.Principal = &other
			case "session":
				b.Scope.SessionID = &other
			case "incarnation":
				b.Scope.SessionIncarnation = &other
			case "local":
				b.Scope.LocalNonce = &other
			}
			c := challenge(t)
			pe, fe := envelopes(t, p, c)
			_, e := Accept(pe, fe, fixtureTrust(), b, c, nil, testNow)
			if e == nil || e.Error() != "wrong_binding" {
				t.Fatal(e)
			}
		})
	}
	c := challenge(t)
	pe, fe := envelopes(t, p, c)
	if _, e := Accept(pe, fe, fixtureTrust(), binding(p), c, nil, testNow); e != nil {
		t.Fatal(e)
	}
}
func TestEnvelopeConstraints(t *testing.T) {
	payload := []byte(`{"valid":true}`)
	raw := signed(t, PolicyRole, "policy", payload, 32)
	if got, e := Verify(raw, PolicyRole, fixtureTrust(), testNow); e != nil || !bytes.Equal(got, payload) {
		t.Fatal(e)
	}
	if _, e := Verify(raw, FreshnessRole, fixtureTrust(), testNow); e == nil || e.Error() != "wrong_role" {
		t.Fatal(e)
	}
	if _, e := Verify(signed(t, PolicyRole, "policy", payload, rsa.PSSSaltLengthAuto), PolicyRole, fixtureTrust(), testNow); e == nil {
		t.Fatal("accepted non-32 salt")
	}
	for _, change := range []func(*Trust){func(tr *Trust) { tr.RootVersion = 2 }, func(tr *Trust) { tr.Keys[0].Role = "bootstrap-release.v1" }, func(tr *Trust) { tr.Keys[0].NotAfter = testNow }, func(tr *Trust) { tr.Keys = append(tr.Keys, tr.Keys[0]) }, func(tr *Trust) { tr.Keys[0].Public = &rsa.PublicKey{N: private.N, E: 3} }} {
		tr := fixtureTrust()
		change(&tr)
		if _, e := Verify(raw, PolicyRole, tr, testNow); e == nil {
			t.Fatal("accepted invalid trust")
		}
	}
	var env contracts.Envelope
	json.Unmarshal(raw, &env)
	env.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"valid":false}`))
	tampered, _ := json.Marshal(env)
	if _, e := Verify(tampered, PolicyRole, fixtureTrust(), testNow); e == nil {
		t.Fatal("accepted tampered payload")
	}
	env.Protected += "="
	tampered, _ = json.Marshal(env)
	if _, e := Verify(tampered, PolicyRole, fixtureTrust(), testNow); e == nil {
		t.Fatal("accepted noncanonical base64")
	}
}
func TestDurableCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "authority.journal")
	store, e := OpenStore(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	contender, stop := context.WithTimeout(ctx, 80*time.Millisecond)
	defer stop()
	if _, e = OpenStore(contender, path); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("concurrent writer", e)
	}
	p := policy()
	c := challenge(t)
	pe, fe := envelopes(t, p, c)
	first, e := Accept(pe, fe, fixtureTrust(), binding(p), c, nil, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Commit(nil, first.Checkpoint); e != nil {
		t.Fatal(e)
	}
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	store, e = OpenStore(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := store.Load()
	if e != nil || *loaded != first.Checkpoint {
		t.Fatal("restart lost floor", e)
	}
	if e = store.Commit(nil, first.Checkpoint); e == nil {
		t.Fatal("accepted stale compare-and-swap")
	}
	store.Close()
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte{0, 0})
	f.Close()
	if _, e = OpenStore(ctx, path); e == nil {
		t.Fatal("accepted torn checkpoint")
	}
}
func TestCrossLanguagePSS(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Fatal("Node 24 is required for cross-language test vectors")
	}
	script := "../../../packages/module-contracts/scripts/pss-vector.mjs"
	output, e := exec.Command(node, script, "--sign").CombinedOutput()
	if e != nil {
		t.Fatalf("%v %s", e, output)
	}
	var vector struct {
		PublicKey string             `json:"publicKey"`
		Envelope  contracts.Envelope `json:"envelope"`
	}
	if e = json.Unmarshal(output, &vector); e != nil {
		t.Fatal(e)
	}
	der, e := base64.StdEncoding.DecodeString(vector.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		t.Fatal(e)
	}
	tr := fixtureTrust()
	tr.Keys[0].Public = pub.(*rsa.PublicKey)
	raw, _ := json.Marshal(vector.Envelope)
	if _, e = Verify(raw, PolicyRole, tr, testNow); e != nil {
		t.Fatal("Node signature rejected", e)
	}
	raw = signed(t, PolicyRole, "policy", []byte("Go exact bytes\n"), 32)
	json.Unmarshal(raw, &vector.Envelope)
	der, e = x509.MarshalPKIXPublicKey(&private.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	vector.PublicKey = base64.StdEncoding.EncodeToString(der)
	input, _ := json.Marshal(vector)
	cmd := exec.Command(node, script, "--verify")
	cmd.Stdin = bytes.NewReader(input)
	if output, e = cmd.CombinedOutput(); e != nil {
		t.Fatalf("Node rejected Go signature: %v %s", e, output)
	}
}
