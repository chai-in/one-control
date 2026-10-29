package lifecycle

import (
	"context"
	"encoding/base64"
	"errors"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"reflect"
	"slices"
	"time"
)

type FeatureResult struct {
	Module, Version, Operation, PolicyDigest string
	Payload                                  []byte
}

// Invoke holds the lifecycle owner through one bounded feature operation, so
// selection changes cannot replace its host while the request is executing.
// Callers use fixed operation/permission mappings; features never receive the
// enrollment credential, signer material, or a control-plane URL.
func (m *Manager) Invoke(ctx context.Context, module, permission, operation string, payload []byte) (FeatureResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result FeatureResult
	if err := m.usable(); err != nil {
		return result, err
	}
	if m.unknown() {
		return result, ErrUnknown
	}
	if m.state == nil || m.state.Active == "" || m.state.Active != m.state.Healthy || m.state.Candidate != "" {
		return result, errors.New("no_healthy_generation")
	}
	now := time.Now()
	if now.Unix() < m.state.Checkpoint.SeenAt {
		return result, errors.New("clock_rollback")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(m.state.PolicyEnvelope)
	if err != nil {
		return result, err
	}
	policyBytes, err := authority.Verify(raw, authority.PolicyRole, m.options.Trust, now.Unix())
	if err != nil {
		return result, err
	}
	var policy contracts.Policy
	if _, err = contracts.Decode(policyBytes, "Policy", &policy); err != nil {
		return result, err
	}
	if now.Unix() >= policy.ExpiresAt {
		return result, errors.New("expired")
	}
	version := policy.Enabled[module]
	if version == "" || slices.Contains(policy.Disabled, module) {
		return result, errors.New("module_disabled")
	}
	if !slices.Contains(policy.AllowedPermissions, permission) {
		return result, errors.New("permission_not_granted")
	}
	var generation *contracts.Generation
	for i := range m.state.Generations {
		if m.state.Generations[i].Identity == m.state.Healthy {
			generation = &m.state.Generations[i]
			break
		}
	}
	if generation == nil || !reflect.DeepEqual(generation.Roots, policy.Enabled) {
		return result, errors.New("selection_not_active")
	}
	packageID := ""
	for _, installed := range m.state.Packages {
		manifest := installed.Entry.Manifest
		if manifest.ID == module && manifest.Version == version && manifest.Kind == "feature" && installed.State == "published" && slices.Contains(generation.Packages, installed.Identity) {
			if !slices.Contains(manifest.Permissions, permission) {
				return result, errors.New("permission_not_declared")
			}
			packageID = installed.Identity
			break
		}
	}
	if packageID == "" {
		return result, errors.New("feature_not_active")
	}
	for _, attempt := range m.state.Attempts {
		if attempt.Generation != generation.Identity || attempt.Package != packageID || attempt.State != "intent" {
			continue
		}
		child := m.children[attempt.Instance]
		if child == nil {
			continue
		}
		deadline := time.Unix(policy.ExpiresAt, 0)
		operationCtx, cancel := context.WithDeadline(ctx, deadline)
		response, err := child.Request(operationCtx, operation, payload, 25*time.Second)
		cancel()
		if err != nil {
			return result, errors.Join(err, m.stopAll())
		}
		return FeatureResult{Module: module, Version: version, Operation: operation, PolicyDigest: m.state.Checkpoint.PolicyDigest, Payload: response}, nil
	}
	return result, errors.New("feature_not_active")
}
