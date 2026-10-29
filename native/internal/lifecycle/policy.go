package lifecycle

import (
	"encoding/base64"
	"errors"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
)

// Policy returns the current verified policy without granting new activation.
func (m *Manager) Policy(now int64) (contracts.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var policy contracts.Policy
	if err := m.usable(); err != nil {
		return policy, err
	}
	if m.state == nil {
		return policy, errors.New("native_policy_unavailable")
	}
	if now < m.state.Checkpoint.SeenAt {
		return policy, errors.New("clock_rollback")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(m.state.PolicyEnvelope)
	if err != nil {
		return policy, err
	}
	payload, err := authority.Verify(raw, authority.PolicyRole, m.options.Trust, now)
	if err != nil {
		return policy, err
	}
	if _, err = contracts.Decode(payload, "Policy", &policy); err != nil {
		return policy, err
	}
	if now >= policy.ExpiresAt {
		return policy, errors.New("expired")
	}
	return policy, nil
}

// Suspend records quiescence but retains packages and authority floors.
func (m *Manager) Suspend() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.usable(); err != nil {
		return err
	}
	return m.stopAll()
}
