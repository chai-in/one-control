package authority

import (
	"encoding/json"
	"errors"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/selection"
	"strconv"
)

const CatalogRole = "module-catalog.v2"

type Selection struct {
	Accepted Accepted
	Catalog  contracts.ModuleCatalog
	Floor    contracts.CatalogFloor
	Plan     contracts.Plan
}

func ValidateCatalog(c contracts.ModuleCatalog) error {
	seen := map[string]bool{}
	entries := map[string]contracts.CatalogEntry{}
	for _, entry := range c.Entries {
		m := entry.Manifest
		key := m.ID + "@" + m.Version
		if seen[key] || len(m.Artifacts) == 0 || len(m.Artifacts) != len(entry.Platforms) {
			return errors.New("invalid_catalog")
		}
		seen[key] = true
		entries[key] = entry
		for platform := range m.Artifacts {
			metadata, ok := entry.Platforms[platform]
			if !ok || metadata.Scope != "machine" || (m.Kind == "shared" && (metadata.Layout != "passive-v1" || metadata.HostAbi != "none")) || (m.Kind == "feature" && (metadata.Layout != "native-host-v1" || metadata.HostAbi != "one-control-host-v1")) {
				return errors.New("unsupported_host_shape")
			}
		}
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(key string) error {
		if visiting[key] {
			return errors.New("invalid_catalog_dependency")
		}
		if visited[key] {
			return nil
		}
		visiting[key] = true
		for id, version := range entries[key].Manifest.Dependencies {
			dependency := id + "@" + version
			target, ok := entries[dependency]
			if !ok || target.Manifest.Kind != "shared" {
				return errors.New("invalid_catalog_dependency")
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		delete(visiting, key)
		visited[key] = true
		return nil
	}
	for key := range entries {
		if err := visit(key); err != nil {
			return err
		}
	}
	return nil
}

func AdvanceCatalog(prior *contracts.CatalogFloor, next contracts.CatalogFloor) error {
	if prior == nil {
		return nil
	}
	if number(next.RootVersion) < number(prior.RootVersion) || number(next.AuthorityEpoch) < number(prior.AuthorityEpoch) {
		return fault("stale_epoch")
	}
	if next.AuthorityEpoch != prior.AuthorityEpoch {
		if number(next.RootVersion) <= number(prior.RootVersion) {
			return fault("stale_epoch")
		}
		return nil
	}
	if number(next.Revision) < number(prior.Revision) {
		return fault("stale_revision")
	}
	if next.Revision == prior.Revision && next.Digest != prior.Digest {
		return fault("equivocation")
	}
	return nil
}

func AcceptSelection(policy, fresh, catalog []byte, trust Trust, binding Binding, challenge *Challenge, previous *contracts.Checkpoint, floor *contracts.CatalogFloor, bootstrap string, now int64) (Selection, error) {
	var out Selection
	raw, err := Verify(catalog, CatalogRole, trust, now)
	if err != nil {
		return out, err
	}
	var c contracts.ModuleCatalog
	if _, err = contracts.Decode(raw, "ModuleCatalog", &c); err != nil {
		return out, err
	}
	if c.IssuedAt > now || c.ExpiresAt <= now || c.ExpiresAt <= c.IssuedAt {
		return out, fault("expired")
	}
	if number(c.AuthorityEpoch) != trust.Epoch {
		return out, fault("stale_epoch")
	}
	if err = ValidateCatalog(c); err != nil {
		return out, err
	}
	next := contracts.CatalogFloor{RootVersion: strconv.FormatUint(trust.RootVersion, 10), AuthorityEpoch: c.AuthorityEpoch, Revision: c.Revision, Digest: hash(raw)}
	if err = AdvanceCatalog(floor, next); err != nil {
		return out, err
	}
	accepted, err := Accept(policy, fresh, trust, binding, challenge, previous, now)
	if err != nil {
		return out, err
	}
	if accepted.Policy.CatalogDigest != next.Digest {
		return out, fault("wrong_catalog_binding")
	}
	if binding.Scope.Kind != "machine" {
		return out, fault("unsupported_host_shape")
	}
	manifests := make([]contracts.Manifest, 0, len(c.Entries))
	for _, entry := range c.Entries {
		manifests = append(manifests, entry.Manifest)
	}
	input, err := json.Marshal(contracts.PlanInput{Catalog: manifests, Enabled: accepted.Policy.Enabled, Disabled: accepted.Policy.Disabled, Platform: binding.Platform, BootstrapVersion: bootstrap, AllowedPermissions: accepted.Policy.AllowedPermissions})
	if err != nil {
		return out, err
	}
	plan, err := selection.Resolve(input)
	if err != nil {
		return out, err
	}
	return Selection{accepted, c, next, plan}, nil
}
