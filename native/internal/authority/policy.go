package authority

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"onecontrol/native/internal/contracts"
	"reflect"
	"strconv"
)

type Binding struct {
	DeviceID, EnrollmentID, Platform string
	Scope                            contracts.Scope
}
type Accepted struct {
	Policy     contracts.Policy
	Checkpoint contracts.Checkpoint
}

// Challenge is created locally for one request. It is consumed on acceptance,
// including when a subsequent durable commit fails. A restart creates a new one.
type Challenge struct {
	nonce    string
	consumed bool
}

func NewChallenge() (*Challenge, error) {
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	return &Challenge{nonce: base64.RawURLEncoding.EncodeToString(nonce[:])}, nil
}
func (c *Challenge) Nonce() string { return c.nonce }

func hash(data []byte) string      { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func number(s string) uint64       { n, _ := strconv.ParseUint(s, 10, 64); return n }
func bindingHash(b Binding) string { data, _ := json.Marshal(b); return hash(data) }

// Accept consumes a locally owned request challenge after successful validation.
// It performs no I/O. The single owner must persist the returned checkpoint
// before any forward effect. Restoring files does not establish fresh authority.
func Accept(policyEnvelope, freshEnvelope []byte, trust Trust, binding Binding, challenge *Challenge, previous *contracts.Checkpoint, now int64) (Accepted, error) {
	var out Accepted
	if challenge == nil || challenge.consumed {
		return out, fault("replayed_challenge")
	}
	nonce := challenge.nonce
	raw, e := Verify(policyEnvelope, PolicyRole, trust, now)
	if e != nil {
		return out, e
	}
	freshRaw, e := Verify(freshEnvelope, FreshnessRole, trust, now)
	if e != nil {
		return out, e
	}
	var p contracts.Policy
	var f contracts.Freshness
	if _, e = contracts.Decode(raw, "Policy", &p); e != nil {
		return out, e
	}
	if _, e = contracts.Decode(freshRaw, "Freshness", &f); e != nil {
		return out, e
	}
	digest := hash(raw)
	if p.DeviceID != binding.DeviceID || p.EnrollmentID != binding.EnrollmentID || p.Platform != binding.Platform || !reflect.DeepEqual(p.Scope, binding.Scope) || f.DeviceID != p.DeviceID || f.EnrollmentID != p.EnrollmentID || f.PolicyDigest != digest || f.Nonce != nonce {
		return out, fault("wrong_binding")
	}
	if p.IssuedAt > now || p.ExpiresAt <= now || p.ExpiresAt <= p.IssuedAt || f.IssuedAt > now || f.ExpiresAt <= now || f.ExpiresAt <= f.IssuedAt || f.ExpiresAt-f.IssuedAt > 300 {
		return out, fault("expired")
	}
	if number(p.AuthorityEpoch) != trust.Epoch || f.AuthorityEpoch != p.AuthorityEpoch {
		return out, fault("stale_epoch")
	}
	bh := bindingHash(binding)
	if previous != nil {
		serialized, _ := json.Marshal(previous)
		var checked contracts.Checkpoint
		if _, e = contracts.Decode(serialized, "Checkpoint", &checked); e != nil {
			return out, fault("invalid_checkpoint")
		}
		if previous.BindingDigest != bh {
			return out, fault("wrong_binding")
		}
		if now < previous.SeenAt {
			return out, fault("clock_rollback")
		}
		oldRoot, oldEpoch := number(previous.RootVersion), number(previous.AuthorityEpoch)
		if trust.RootVersion < oldRoot || trust.Epoch < oldEpoch {
			return out, fault("stale_epoch")
		}
		if trust.Epoch > oldEpoch && trust.RootVersion <= oldRoot {
			return out, fault("stale_epoch")
		}
		if trust.Epoch == oldEpoch {
			if number(p.Revision) < number(previous.Revision) {
				return out, fault("stale_revision")
			}
			if p.Revision == previous.Revision && digest != previous.PolicyDigest {
				return out, fault("equivocation")
			}
		}
		if f.Nonce == previous.Nonce {
			return out, fault("replayed_challenge")
		}
	}
	out.Policy = p
	challenge.consumed = true
	out.Checkpoint = contracts.Checkpoint{RootVersion: fmt.Sprint(trust.RootVersion), AuthorityEpoch: p.AuthorityEpoch, Revision: p.Revision, PolicyDigest: digest, BindingDigest: bh, SeenAt: now, Nonce: f.Nonce}
	return out, nil
}
