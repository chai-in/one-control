package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/selection"
	"os"
	"reflect"
	"strconv"
)

func digest(raw []byte) string                   { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func encoded(v any) []byte                       { b, _ := json.Marshal(v); return b }
func fail() error                                { return errors.New("invalid_lifecycle_journal") }
func generationID(g contracts.Generation) string { g.Identity = ""; return digest(encoded(g)) }

func validateState(s contracts.LifecycleState) error {
	if _, err := contracts.Decode(encoded(s), "LifecycleState", &contracts.LifecycleState{}); err != nil {
		return err
	}
	decodeEnvelope := func(raw string, model string, target any) ([]byte, error) {
		b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != raw {
			return nil, fail()
		}
		var envelope contracts.Envelope
		if _, err = contracts.Decode(b, "Envelope", &envelope); err != nil {
			return nil, err
		}
		payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
		if err != nil {
			return nil, err
		}
		if _, err = contracts.Decode(payload, model, target); err != nil {
			return nil, err
		}
		return payload, nil
	}
	var policy contracts.Policy
	var catalog contracts.ModuleCatalog
	var freshness contracts.Freshness
	policyRaw, err := decodeEnvelope(s.PolicyEnvelope, "Policy", &policy)
	if err != nil {
		return fail()
	}
	catalogRaw, err := decodeEnvelope(s.CatalogEnvelope, "ModuleCatalog", &catalog)
	if err != nil {
		return fail()
	}
	if _, err = decodeEnvelope(s.FreshnessEnvelope, "Freshness", &freshness); err != nil {
		return fail()
	}
	if freshness.Nonce != s.Checkpoint.Nonce || freshness.PolicyDigest != s.Checkpoint.PolicyDigest || freshness.DeviceID != policy.DeviceID || freshness.EnrollmentID != policy.EnrollmentID || freshness.AuthorityEpoch != policy.AuthorityEpoch || freshness.IssuedAt > s.Checkpoint.SeenAt || freshness.ExpiresAt <= s.Checkpoint.SeenAt || freshness.ExpiresAt-freshness.IssuedAt > 300 {
		return fail()
	}
	if digest(policyRaw) != s.Checkpoint.PolicyDigest || digest(catalogRaw) != s.CatalogFloor.Digest || policy.CatalogDigest != s.CatalogFloor.Digest || policy.Revision != s.Checkpoint.Revision || policy.AuthorityEpoch != s.Checkpoint.AuthorityEpoch || catalog.Revision != s.CatalogFloor.Revision || catalog.AuthorityEpoch != s.CatalogFloor.AuthorityEpoch || s.CatalogFloor.AuthorityEpoch != s.Checkpoint.AuthorityEpoch || s.CatalogFloor.RootVersion != s.Checkpoint.RootVersion || authority.ValidateCatalog(catalog) != nil {
		return fail()
	}
	if policy.IssuedAt > s.Checkpoint.SeenAt || policy.ExpiresAt <= s.Checkpoint.SeenAt || catalog.IssuedAt > s.Checkpoint.SeenAt || catalog.ExpiresAt <= s.Checkpoint.SeenAt {
		return fail()
	}
	packages := map[string]contracts.PublishedPackage{}
	for _, p := range s.Packages {
		if _, exists := packages[p.Identity]; exists {
			return fail()
		}
		if _, ok := p.Entry.Platforms[p.Platform]; !ok {
			return fail()
		}
		if p.Identity != packageIdentity(p) {
			return fail()
		}
		meta := p.Entry.Platforms[p.Platform]
		var att contracts.Envelope
		raw, err := base64.RawURLEncoding.Strict().DecodeString(p.Attestation)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != p.Attestation || digest(raw) != meta.AttestationSha256 {
			return fail()
		}
		if _, err = contracts.Decode(raw, "Envelope", &att); err != nil {
			return fail()
		}
		payload, err := base64.RawURLEncoding.Strict().DecodeString(att.Payload)
		if err != nil {
			return fail()
		}
		if _, err = contracts.Decode(payload, "PackageAttestation", &contracts.PackageAttestation{}); err != nil {
			return fail()
		}
		packages[p.Identity] = p
	}
	for _, p := range packages {
		for id, version := range p.Entry.Manifest.Dependencies {
			found := false
			for _, dep := range packages {
				if dep.Platform == p.Platform && dep.Entry.Manifest.ID == id && dep.Entry.Manifest.Version == version {
					found = true
				}
			}
			if !found {
				return fail()
			}
		}
	}
	gens := map[string]bool{}
	for _, g := range s.Generations {
		if gens[g.Identity] || g.Identity != generationID(g) {
			return fail()
		}
		gens[g.Identity] = true
		seen := map[string]bool{}
		for _, id := range g.Packages {
			if seen[id] {
				return fail()
			}
			if _, ok := packages[id]; !ok {
				return fail()
			}
			seen[id] = true
		}
		for id, version := range g.Roots {
			found := false
			for key := range seen {
				m := packages[key].Entry.Manifest
				if m.ID == id && m.Version == version && m.Kind == "feature" {
					found = true
				}
			}
			if !found {
				return fail()
			}
		}
		for key := range seen {
			for id, version := range packages[key].Entry.Manifest.Dependencies {
				found := false
				for dep := range seen {
					m := packages[dep].Entry.Manifest
					if m.ID == id && m.Version == version {
						found = true
					}
				}
				if !found {
					return fail()
				}
			}
		}
	}
	for _, pointer := range []string{s.Candidate, s.Active, s.Healthy} {
		if pointer != "" && !gens[pointer] {
			return fail()
		}
	}
	instances := map[string]bool{}
	for _, a := range s.Attempts {
		if instances[a.Instance] || !gens[a.Generation] {
			return fail()
		}
		if _, exists := packages[a.Package]; !exists {
			return fail()
		}
		member := false
		for _, g := range s.Generations {
			if g.Identity == a.Generation {
				for _, id := range g.Packages {
					if id == a.Package && packages[id].Entry.Manifest.Kind == "feature" {
						member = true
					}
				}
			}
		}
		if !member {
			return fail()
		}
		instances[a.Instance] = true
	}
	trash := map[string]bool{}
	for _, id := range s.Trash {
		if trash[id] {
			return fail()
		}
		if _, exists := packages[id]; !exists {
			return fail()
		}
		trash[id] = true
	}
	for _, pointer := range []string{s.Candidate, s.Active, s.Healthy} {
		for _, g := range s.Generations {
			if g.Identity == pointer {
				for _, id := range g.Packages {
					if trash[id] {
						return fail()
					}
				}
			}
		}
	}
	for _, a := range s.Attempts {
		if a.State != "stopped" && trash[a.Package] {
			return fail()
		}
	}
	return nil
}

func validateAdvance(old *contracts.LifecycleState, next contracts.LifecycleState) error {
	if err := validateState(next); err != nil {
		return err
	}
	var policy contracts.Policy
	var catalog contracts.ModuleCatalog
	decode := func(s, model string, target any) {
		raw, _ := base64.RawURLEncoding.DecodeString(s)
		var env contracts.Envelope
		_ = json.Unmarshal(raw, &env)
		payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
		_, _ = contracts.Decode(payload, model, target)
	}
	decode(next.PolicyEnvelope, "Policy", &policy)
	decode(next.CatalogEnvelope, "ModuleCatalog", &catalog)
	manifests := []contracts.Manifest{}
	entries := map[string]contracts.CatalogEntry{}
	for _, entry := range catalog.Entries {
		manifests = append(manifests, entry.Manifest)
		entries[entry.Manifest.ID+"@"+entry.Manifest.Version] = entry
	}
	plan, err := selection.Resolve(encoded(contracts.PlanInput{Catalog: manifests, Enabled: policy.Enabled, Disabled: policy.Disabled, Platform: policy.Platform, BootstrapVersion: "99999.99999.99999", AllowedPermissions: policy.AllowedPermissions}))
	if err != nil {
		return fail()
	}
	authorized := map[string]bool{}
	for _, p := range plan.Packages {
		authorized[p.Key] = true
	}
	oldPackages := map[string]contracts.PublishedPackage{}
	oldGenerations := map[string]contracts.Generation{}
	oldAttempts := map[string]contracts.HostAttempt{}
	if old != nil {
		for _, p := range old.Packages {
			oldPackages[p.Identity] = p
		}
		for _, g := range old.Generations {
			oldGenerations[g.Identity] = g
		}
		for _, a := range old.Attempts {
			oldAttempts[a.Instance] = a
		}
	}
	for _, p := range next.Packages {
		prior, exists := oldPackages[p.Identity]
		if exists {
			before, after := prior, p
			before.State = ""
			after.State = ""
			if !reflect.DeepEqual(before, after) {
				return fail()
			}
		} else {
			key := p.Entry.Manifest.ID + "@" + p.Entry.Manifest.Version
			if !authorized[key] || p.Platform != policy.Platform || !reflect.DeepEqual(entries[key], p.Entry) || p.State != "intent" || p.VerifiedAt != next.Checkpoint.SeenAt {
				return fail()
			}
		}
		delete(oldPackages, p.Identity)
	}
	if len(oldPackages) != 0 {
		return fail()
	}
	authorizedGeneration := func(g contracts.Generation) bool {
		if !reflect.DeepEqual(g.Roots, policy.Enabled) || len(g.Packages) != len(plan.Packages) {
			return false
		}
		for i, planned := range plan.Packages {
			found := false
			for _, p := range next.Packages {
				if p.Identity == g.Packages[i] && p.State == "published" && p.Platform == policy.Platform && reflect.DeepEqual(p.Entry, entries[planned.Key]) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	for _, g := range next.Generations {
		prior, exists := oldGenerations[g.Identity]
		if exists {
			if !reflect.DeepEqual(prior, g) {
				return fail()
			}
		} else if !authorizedGeneration(g) {
			return fail()
		}
		delete(oldGenerations, g.Identity)
	}
	if len(oldGenerations) != 0 {
		return fail()
	}
	for i, pointer := range []string{next.Candidate, next.Active} {
		if pointer == "" {
			continue
		}
		changed := old == nil
		if old != nil {
			if i == 0 {
				changed = pointer != old.Candidate
			} else {
				changed = pointer != old.Active
			}
		}
		if changed {
			found := false
			for _, g := range next.Generations {
				if g.Identity == pointer && authorizedGeneration(g) {
					found = true
				}
			}
			if !found {
				return fail()
			}
		}
	}
	for _, attempt := range next.Attempts {
		if _, exists := oldAttempts[attempt.Instance]; !exists && (attempt.State != "intent" || attempt.Generation != next.Candidate) {
			return fail()
		}
	}
	if old != nil && next.Healthy != old.Healthy && (next.Healthy != next.Active || next.Candidate != "") {
		return fail()
	}
	n, _ := strconv.ParseUint(next.Sequence, 10, 64)
	if old == nil {
		if n != 1 {
			return fail()
		}
		return nil
	}
	prior, _ := strconv.ParseUint(old.Sequence, 10, 64)
	if prior == ^uint64(0) || n != prior+1 {
		return fail()
	}
	if err := authority.AdvanceCatalog(&old.CatalogFloor, next.CatalogFloor); err != nil {
		return fail()
	}
	a, b := old.Checkpoint, next.Checkpoint
	parse := func(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
	if a.BindingDigest != b.BindingDigest || b.SeenAt < a.SeenAt || parse(b.RootVersion) < parse(a.RootVersion) || parse(b.AuthorityEpoch) < parse(a.AuthorityEpoch) {
		return fail()
	}
	if a.AuthorityEpoch == b.AuthorityEpoch {
		if parse(b.Revision) < parse(a.Revision) || (a.Revision == b.Revision && a.PolicyDigest != b.PolicyDigest) {
			return fail()
		}
	} else if parse(b.RootVersion) <= parse(a.RootVersion) {
		return fail()
	}
	for _, attempt := range old.Attempts {
		found := false
		for _, current := range next.Attempts {
			if current.Instance == attempt.Instance {
				if current.Generation != attempt.Generation || current.Package != attempt.Package || (attempt.State != "intent" && current.State != attempt.State) {
					return fail()
				}
				found = true
			}
		}
		if !found {
			return fail()
		}
	}
	return nil
}

func readJournal(root *os.Root, verify func(contracts.LifecycleState) error) (*contracts.LifecycleState, error) {
	f, err := root.Open("generations.log")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, fail()
	}
	var prior *contracts.LifecycleState
	for {
		var size [4]byte
		_, err = io.ReadFull(f, size[:])
		if err == io.EOF {
			return prior, nil
		}
		if err != nil {
			return nil, fail()
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < 1 || n > 6<<20 {
			return nil, fail()
		}
		payload := make([]byte, n)
		var sum [32]byte
		if _, err = io.ReadFull(f, payload); err != nil {
			return nil, fail()
		}
		if _, err = io.ReadFull(f, sum[:]); err != nil {
			return nil, fail()
		}
		actual := sha256.Sum256(payload)
		if !bytes.Equal(sum[:], actual[:]) {
			return nil, fail()
		}
		var s contracts.LifecycleState
		if _, err = contracts.Decode(payload, "LifecycleState", &s); err != nil {
			return nil, fail()
		}
		if err = validateAdvance(prior, s); err != nil {
			return nil, err
		}
		if verify != nil {
			if err = verify(s); err != nil {
				return nil, err
			}
		}
		prior = &s
	}
}

func (m *Manager) commit(next contracts.LifecycleState, boundary string) error {
	seq := uint64(0)
	if m.state != nil {
		seq, _ = strconv.ParseUint(m.state.Sequence, 10, 64)
	}
	if seq == ^uint64(0) {
		return fail()
	}
	next.Sequence = strconv.FormatUint(seq+1, 10)
	if err := validateAdvance(m.state, next); err != nil {
		return err
	}
	payload := encoded(next)
	if len(payload) > 6<<20 {
		return fail()
	}
	f, err := m.root.OpenFile("generations.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || info.Size()+int64(len(payload))+36 > 64<<20 {
		f.Close()
		return fail()
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	frame = append(frame, payload...)
	sum := sha256.Sum256(payload)
	frame = append(frame, sum[:]...)
	n, err := f.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		m.poisoned = true
		return err
	}
	m.state = &next
	if m.boundary != nil {
		m.boundary(boundary)
	}
	return nil
}
