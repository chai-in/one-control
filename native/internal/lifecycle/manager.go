package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/ownership"
	"onecontrol/native/internal/packages"
	"onecontrol/native/internal/processhost"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
)

var ErrUnknown = errors.New("prior native host custody is unknown; activation and collection are blocked")

type Options struct {
	Root             string
	Trust            authority.Trust
	Binding          authority.Binding
	BootstrapVersion string
	Delivery         *packages.Delivery
}

type Manager struct {
	mu       sync.Mutex
	options  Options
	root     *os.Root
	owner    *ownership.Owner
	state    *contracts.LifecycleState
	children map[string]*processhost.Child
	poisoned bool
	boundary func(string)
}

type Request struct {
	Policy, Freshness, Catalog []byte
	Challenge                  *authority.Challenge
	Attestations               map[string][]byte
	Now                        int64
}

func Open(ctx context.Context, o Options) (*Manager, error) {
	if o.Delivery == nil || !filepath.IsAbs(o.Root) || !o.Delivery.ControlsRoot(o.Root) {
		return nil, errors.New("controlled absolute root and delivery are required")
	}
	o.Trust.Keys = append([]authority.Key(nil), o.Trust.Keys...)
	for i := range o.Trust.Keys {
		k := &o.Trust.Keys[i]
		if k.Public != nil && k.Public.N != nil {
			k.Public = &rsa.PublicKey{N: new(big.Int).Set(k.Public.N), E: k.Public.E}
		}
	}
	if o.Binding.Scope.Kind != "machine" {
		return nil, errors.New("unsupported_host_shape")
	}
	owner, err := ownership.Acquire(ctx, filepath.Join(o.Root, "feature-owner.lock"))
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(o.Root)
	if err != nil {
		owner.Close()
		return nil, err
	}
	state, err := readJournal(root, func(state contracts.LifecycleState) error {
		var policy contracts.Policy
		for _, envelope := range []struct{ raw, role string }{{state.PolicyEnvelope, authority.PolicyRole}, {state.FreshnessEnvelope, authority.FreshnessRole}, {state.CatalogEnvelope, authority.CatalogRole}} {
			raw, e := base64.RawURLEncoding.Strict().DecodeString(envelope.raw)
			if e == nil {
				var payload []byte
				payload, e = authority.Verify(raw, envelope.role, o.Trust, state.Checkpoint.SeenAt)
				if e == nil && envelope.role == authority.PolicyRole {
					_, e = contracts.Decode(payload, "Policy", &policy)
				}
			}
			if e != nil {
				return e
			}
		}
		if policy.DeviceID != o.Binding.DeviceID || policy.EnrollmentID != o.Binding.EnrollmentID || policy.Platform != o.Binding.Platform || !reflect.DeepEqual(policy.Scope, o.Binding.Scope) || state.Checkpoint.BindingDigest != digest(encoded(o.Binding)) {
			return errors.New("wrong_binding")
		}
		if state.Checkpoint.RootVersion != fmt.Sprint(o.Trust.RootVersion) || state.Checkpoint.AuthorityEpoch != fmt.Sprint(o.Trust.Epoch) {
			return errors.New("wrong_root")
		}
		for _, p := range state.Packages {
			if e := o.Delivery.CheckAttestation(approval(p), attestation(p), p.VerifiedAt); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		root.Close()
		owner.Close()
		return nil, err
	}
	m := &Manager{options: o, root: root, owner: owner, state: state, children: map[string]*processhost.Child{}}
	if state != nil {
		next := m.snapshot()
		changed := false
		for i := range next.Attempts {
			if next.Attempts[i].State == "intent" {
				next.Attempts[i].State = "unknown"
				changed = true
			}
		}
		if changed {
			if err = m.commit(next, "recovery-unknown"); err != nil {
				root.Close()
				owner.Close()
				return nil, err
			}
		}
	}
	return m, nil
}

func (m *Manager) snapshot() contracts.LifecycleState {
	if m.state == nil {
		return contracts.LifecycleState{SchemaVersion: 1, Packages: []contracts.PublishedPackage{}, Generations: []contracts.Generation{}, Attempts: []contracts.HostAttempt{}, Trash: []string{}}
	}
	var s contracts.LifecycleState
	_ = json.Unmarshal(encoded(m.state), &s)
	return s
}

func (m *Manager) Snapshot() *contracts.LifecycleState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return nil
	}
	s := m.snapshot()
	return &s
}

func approval(p contracts.PublishedPackage) packages.Approval {
	m := p.Entry.Manifest
	meta := p.Entry.Platforms[p.Platform]
	a := m.Artifacts[p.Platform]
	return packages.Approval{ID: m.ID, Version: m.Version, Platform: p.Platform, Publisher: meta.Publisher, Layout: meta.Layout, URL: a.URL, SHA256: a.SHA256, Size: a.Size}
}
func attestation(p contracts.PublishedPackage) []byte {
	b, _ := base64.RawURLEncoding.Strict().DecodeString(p.Attestation)
	return b
}
func packageIdentity(p contracts.PublishedPackage) string {
	return packages.Identity(approval(p), attestation(p))
}
func (m *Manager) usable() error {
	if m.owner == nil {
		return os.ErrClosed
	}
	if m.poisoned {
		return fail()
	}
	return nil
}
func (m *Manager) unknown() bool {
	if m.state != nil {
		for _, a := range m.state.Attempts {
			if a.State == "unknown" {
				return true
			}
		}
	}
	return false
}

func (m *Manager) Reconcile(ctx context.Context, request Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.usable(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return processhost.ErrUnsupported
	}
	platform := "win-" + map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if m.options.Binding.Platform != platform {
		return errors.New("unsupported_platform")
	}
	var checkpoint *contracts.Checkpoint
	var floor *contracts.CatalogFloor
	if m.state != nil {
		checkpoint = &m.state.Checkpoint
		floor = &m.state.CatalogFloor
	}
	selection, err := authority.AcceptSelection(request.Policy, request.Freshness, request.Catalog, m.options.Trust, m.options.Binding, request.Challenge, checkpoint, floor, m.options.BootstrapVersion, request.Now)
	if err != nil {
		return err
	}
	selected := make([]contracts.PublishedPackage, 0, len(selection.Plan.Packages))
	for _, planned := range selection.Plan.Packages {
		var entry contracts.CatalogEntry
		for _, e := range selection.Catalog.Entries {
			if e.Manifest.ID == planned.Manifest.ID && e.Manifest.Version == planned.Manifest.Version {
				entry = e
				break
			}
		}
		raw := append([]byte(nil), request.Attestations[planned.Key]...)
		if digest(raw) != entry.Platforms[m.options.Binding.Platform].AttestationSha256 {
			return errors.New("wrong_attestation_binding")
		}
		p := contracts.PublishedPackage{Entry: entry, Platform: m.options.Binding.Platform, Attestation: base64.RawURLEncoding.EncodeToString(raw), VerifiedAt: request.Now, State: "intent"}
		p.Identity = packageIdentity(p)
		if err = m.options.Delivery.CheckAttestation(approval(p), raw, request.Now); err != nil {
			return err
		}
		selected = append(selected, p)
	}
	next := m.snapshot()
	next.Checkpoint = selection.Accepted.Checkpoint
	next.CatalogFloor = selection.Floor
	next.PolicyEnvelope = base64.RawURLEncoding.EncodeToString(append([]byte(nil), request.Policy...))
	next.CatalogEnvelope = base64.RawURLEncoding.EncodeToString(append([]byte(nil), request.Catalog...))
	next.FreshnessEnvelope = base64.RawURLEncoding.EncodeToString(append([]byte(nil), request.Freshness...))
	if err = m.commit(next, "authority-flush"); err != nil {
		return err
	}
	if m.unknown() {
		return ErrUnknown
	}
	for _, p := range selected {
		found := false
		published := false
		for _, old := range m.state.Packages {
			if old.Identity == p.Identity {
				found = true
				published = old.State == "published"
				break
			}
		}
		wasTrash := false
		for _, id := range m.state.Trash {
			if id == p.Identity {
				wasTrash = true
			}
		}
		if found && published && !wasTrash {
			if err = m.options.Delivery.VerifyPublished(approval(p), attestation(p), request.Now); err != nil {
				return err
			}
			continue
		}
		if wasTrash {
			if err = m.options.Delivery.FinishTrash(approval(p), attestation(p), request.Now); err != nil {
				return err
			}
		}
		next = m.snapshot()
		if !found {
			next.Packages = append(next.Packages, p)
		} else {
			for i := range next.Packages {
				if next.Packages[i].Identity == p.Identity {
					next.Packages[i].State = "intent"
				}
			}
		}
		retainedTrash := []string{}
		for _, id := range next.Trash {
			if id != p.Identity {
				retainedTrash = append(retainedTrash, id)
			}
		}
		next.Trash = retainedTrash
		if err = m.commit(next, "publication-intent"); err != nil {
			return err
		}
		exists, e := m.options.Delivery.HasPublished(approval(p), attestation(p))
		if e != nil {
			return e
		}
		if exists {
			if err = m.options.Delivery.VerifyPublished(approval(p), attestation(p), request.Now); err != nil {
				return err
			}
		} else {
			if err = ctx.Err(); err != nil {
				return err
			}
			receipt, e := m.options.Delivery.Stage(ctx, approval(p), attestation(p), request.Now)
			if e != nil {
				return e
			}
			if m.boundary != nil {
				m.boundary("stage")
			}
			if _, e = m.options.Delivery.Publish(receipt, approval(p), attestation(p), request.Now); e != nil {
				return e
			}
			if m.boundary != nil {
				m.boundary("publication")
			}
		}
		next = m.snapshot()
		for i := range next.Packages {
			if next.Packages[i].Identity == p.Identity {
				next.Packages[i].State = "published"
			}
		}
		if err = m.commit(next, "publication-receipt"); err != nil {
			return err
		}
	}
	g := contracts.Generation{Packages: []string{}, Roots: selection.Accepted.Policy.Enabled}
	for _, p := range selected {
		g.Packages = append(g.Packages, p.Identity)
	}
	g.Identity = generationID(g)
	expectedHosts := 0
	for _, p := range selected {
		if p.Entry.Manifest.Kind == "feature" {
			expectedHosts++
		}
	}
	if m.state.Active == g.Identity && len(m.children) == expectedHosts {
		for _, child := range m.children {
			if err = child.Health(); err != nil {
				return errors.Join(err, m.stopAll())
			}
		}
		return nil
	}
	next = m.snapshot()
	found := false
	for _, old := range next.Generations {
		if old.Identity == g.Identity {
			found = true
		}
	}
	if !found {
		next.Generations = append(next.Generations, g)
	}
	next.Candidate = g.Identity
	if err = m.commit(next, "candidate-intent"); err != nil {
		return err
	}
	if err = m.stopAll(); err != nil {
		return err
	}
	for _, p := range selected {
		if p.Entry.Manifest.Kind != "feature" {
			continue
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		instance := hex.EncodeToString(nonce[:])
		next = m.snapshot()
		next.Attempts = append(next.Attempts, contracts.HostAttempt{Instance: instance, Generation: g.Identity, Package: p.Identity, State: "intent"})
		if err = m.commit(next, "instance-intent"); err != nil {
			return err
		}
		exe, e := m.options.Delivery.FixedExecutable(approval(p), attestation(p), request.Now)
		if e != nil {
			return e
		}
		child, e := processhost.Start(processhost.Config{Executable: exe, Instance: instance, ReadinessTimeout: 3 * time.Second, OperationTimeout: time.Second, StopTimeout: time.Second})
		if e != nil {
			next = m.snapshot()
			next.Attempts[len(next.Attempts)-1].State = "unknown"
			_ = m.commit(next, "launch-unknown")
			return e
		}
		m.children[instance] = child
		if m.boundary != nil {
			m.boundary("process-creation")
		}
		if err = child.AwaitReady(); err != nil {
			return errors.Join(err, m.stopAll())
		}
		if m.boundary != nil {
			m.boundary("ready")
		}
	}
	next = m.snapshot()
	next.Active = g.Identity
	next.Candidate = ""
	if err = m.commit(next, "active-commit"); err != nil {
		return err
	}
	for _, child := range m.children {
		if err = child.Activate(); err != nil {
			return errors.Join(err, m.stopAll())
		}
		if err = child.Health(); err != nil {
			return errors.Join(err, m.stopAll())
		}
	}
	if m.boundary != nil {
		m.boundary("health")
	}
	next = m.snapshot()
	next.Healthy = g.Identity
	return m.commit(next, "healthy-commit")
}

func (m *Manager) stopAll() error {
	for instance, child := range m.children {
		_, err := child.Stop()
		next := m.snapshot()
		for i := range next.Attempts {
			if next.Attempts[i].Instance == instance {
				if err == nil && child.CanCollect() {
					next.Attempts[i].State = "stopped"
				} else {
					next.Attempts[i].State = "unknown"
				}
			}
		}
		if e := m.commit(next, "stop-proof"); e != nil {
			return errors.Join(err, e)
		}
		if err != nil {
			return err
		}
		delete(m.children, instance)
	}
	return nil
}

func (m *Manager) Collect(now int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.usable(); err != nil {
		return err
	}
	if m.unknown() {
		return ErrUnknown
	}
	if m.state == nil {
		return nil
	}
	if now < m.state.Checkpoint.SeenAt {
		return errors.New("clock_rollback")
	}
	pinned := map[string]bool{}
	for _, g := range m.state.Generations {
		if g.Identity == m.state.Candidate || g.Identity == m.state.Active || g.Identity == m.state.Healthy {
			for _, id := range g.Packages {
				pinned[id] = true
			}
		}
	}
	for _, a := range m.state.Attempts {
		if a.State != "stopped" {
			pinned[a.Package] = true
		}
	}
	for _, p := range m.state.Packages {
		already := false
		for _, id := range m.state.Trash {
			if id == p.Identity {
				already = true
			}
		}
		if already {
			if err := m.options.Delivery.FinishTrash(approval(p), attestation(p), p.VerifiedAt); err != nil {
				return err
			}
			continue
		}
		if p.State == "intent" {
			exists, err := m.options.Delivery.HasPublished(approval(p), attestation(p))
			if err != nil {
				return err
			}
			if !exists {
				continue
			}
		}
		if err := m.options.Delivery.VerifyPublished(approval(p), attestation(p), p.VerifiedAt); err != nil {
			return err
		}
	}
	for _, p := range m.state.Packages {
		if pinned[p.Identity] {
			continue
		}
		already := false
		for _, id := range m.state.Trash {
			if id == p.Identity {
				already = true
			}
		}
		if already {
			continue
		}
		next := m.snapshot()
		next.Trash = append(next.Trash, p.Identity)
		if err := m.commit(next, "trash-intent"); err != nil {
			return err
		}
		exists, err := m.options.Delivery.HasPublished(approval(p), attestation(p))
		if err != nil {
			return err
		}
		if exists {
			if err := m.options.Delivery.Trash(approval(p), attestation(p), p.VerifiedAt); err != nil {
				return err
			}
			if m.boundary != nil {
				m.boundary("trash")
			}
		}
		if err := m.options.Delivery.FinishTrash(approval(p), attestation(p), p.VerifiedAt); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owner == nil {
		return nil
	}
	err := m.stopAll()
	if err != nil {
		return err
	}
	err = errors.Join(m.root.Close(), m.owner.Close())
	m.owner = nil
	return err
}
