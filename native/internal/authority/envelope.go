// Package authority verifies exact signed bytes. Trust is supplied by an
// installation owner, never obtained from an envelope or environment variable.
package authority

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"onecontrol/native/internal/contracts"
)

const PolicyRole = "device-policy.v1"
const FreshnessRole = "policy-freshness.v1"

type Key struct {
	ID, Role            string
	Public              *rsa.PublicKey
	NotBefore, NotAfter int64
}
type Trust struct {
	RootVersion, Epoch uint64
	Keys               []Key
}

func fault(code string) error { return errors.New(code) }
func decode64(s string, max int) ([]byte, error) {
	if len(s) > max*4/3+4 {
		return nil, contracts.ErrWire
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, contracts.ErrWire
	}
	return b, nil
}

// SigningBytes is the sole framing definition. JSON reserialization is never
// used to verify a signature. Lengths are byte lengths, in network byte order.
func SigningBytes(keyID string, protected, payload []byte) []byte {
	b := []byte("ONECONTROL-SIGNED-V1\n")
	for _, part := range [][]byte{[]byte(keyID), protected, payload} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return b
}
func Verify(raw []byte, role string, trust Trust, now int64) ([]byte, error) {
	var env contracts.Envelope
	if _, e := contracts.Decode(raw, "Envelope", &env); e != nil {
		return nil, e
	}
	protected, e := decode64(env.Protected, 4096)
	if e != nil {
		return nil, e
	}
	payload, e := decode64(env.Payload, 4194304)
	if e != nil {
		return nil, e
	}
	signature, e := decode64(env.Signature, 1024)
	if e != nil {
		return nil, e
	}
	var h contracts.Protected
	if _, e = contracts.Decode(protected, "Protected", &h); e != nil {
		return nil, e
	}
	if h.Domain != role {
		return nil, fault("wrong_role")
	}
	if h.RootVersion != fmt.Sprint(trust.RootVersion) {
		return nil, fault("wrong_root")
	}
	seen := map[string]bool{}
	material := map[string]bool{}
	var chosen *Key
	if trust.RootVersion == 0 || trust.Epoch == 0 || len(trust.Keys) > 32 {
		return nil, fault("untrusted_key")
	}
	for i := range trust.Keys {
		k := &trust.Keys[i]
		if k.Public == nil || k.Public.N == nil || k.Public.N.BitLen() < 3072 || k.Public.N.BitLen() > 8192 || k.Public.E != 65537 {
			return nil, fault("untrusted_key")
		}
		fingerprint := k.Public.N.String()
		if seen[k.ID] || material[fingerprint] {
			return nil, fault("untrusted_key")
		}
		seen[k.ID] = true
		material[fingerprint] = true
		if k.ID == h.KeyID {
			chosen = k
		}
	}
	if chosen == nil || chosen.Public == nil || chosen.Public.N == nil || chosen.Public.N.BitLen() < 3072 || chosen.Public.N.BitLen() > 8192 || chosen.Public.E != 65537 {
		return nil, fault("untrusted_key")
	}
	if chosen.Role != role {
		return nil, fault("wrong_role")
	}
	if now < chosen.NotBefore || now >= chosen.NotAfter {
		return nil, fault("expired")
	}
	digest := sha256.Sum256(SigningBytes(h.KeyID, protected, payload))
	if rsa.VerifyPSS(chosen.Public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}) != nil {
		return nil, fault("invalid_signature")
	}
	return payload, nil
}
