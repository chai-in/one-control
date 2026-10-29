//go:build onecontrol_lifecycle_fixture

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestJournalTornAndSemanticCorruption(t *testing.T) {
	f := newFixture(t)
	m := openFixture(t, f)
	request := f.request(t, "1", map[string]string{})
	selected, err := authority.AcceptSelection(request.Policy, request.Freshness, request.Catalog, f.options.Trust, f.options.Binding, request.Challenge, nil, nil, "0.1.0", request.Now)
	if err != nil {
		t.Fatal(err)
	}
	state := m.snapshot()
	state.Checkpoint, state.CatalogFloor = selected.Accepted.Checkpoint, selected.Floor
	state.PolicyEnvelope = base64.RawURLEncoding.EncodeToString(request.Policy)
	state.FreshnessEnvelope = base64.RawURLEncoding.EncodeToString(request.Freshness)
	state.CatalogEnvelope = base64.RawURLEncoding.EncodeToString(request.Catalog)
	if err := m.commit(state, "test-authority-flush"); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.root, "generations.log"))
	if err != nil {
		t.Fatal(err)
	}
	size := int(binary.BigEndian.Uint32(raw[:4])) + 36
	frame := raw[:size]
	root, err := os.OpenRoot(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for cut := 1; cut < len(frame); cut++ {
		if err = os.WriteFile(filepath.Join(f.root, "generations.log"), frame[:cut], 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = readJournal(root, nil); err == nil {
			t.Fatalf("torn frame accepted at %d", cut)
		}
	}
	if err = os.WriteFile(filepath.Join(f.root, "generations.log"), frame, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readJournal(root, nil); err != nil {
		t.Fatal("complete frame rejected", err)
	}
	s := m.snapshot()
	s.Sequence = "1"
	s.Active = "../../outside"
	payload := encoded(s)
	corrupt := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	corrupt = append(corrupt, payload...)
	sum := sha256.Sum256(payload)
	corrupt = append(corrupt, sum[:]...)
	if err = os.WriteFile(filepath.Join(f.root, "generations.log"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readJournal(root, nil); err == nil {
		t.Fatal("checksummed invalid pointer accepted")
	}
	t.Logf("rejected all %d nonempty truncations and checksummed invalid state", len(frame)-1)
}

func TestReplayRejectsSignedForeignBindingAndUnsignedRoot(t *testing.T) {
	for _, row := range []struct {
		name, expected string
		mutate         func(*authority.Binding)
		root           bool
	}{
		{"device", "wrong_binding", func(b *authority.Binding) { b.DeviceID = "foreign-device" }, false},
		{"enrollment", "wrong_binding", func(b *authority.Binding) { b.EnrollmentID = "foreign-enrollment" }, false},
		{"platform", "wrong_binding", func(b *authority.Binding) {
			if b.Platform == "win-x64" {
				b.Platform = "win-arm64"
			} else {
				b.Platform = "win-x64"
			}
		}, false},
		{"machine-scope", "wrong_binding", func(b *authority.Binding) { b.Scope.MachineID = "foreign-machine" }, false},
		{"unsigned-root", "wrong_root", func(*authority.Binding) {}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t)
			local := f.options.Binding
			row.mutate(&f.options.Binding)
			request := f.request(t, "900", map[string]string{})
			selected, err := authority.AcceptSelection(request.Policy, request.Freshness, request.Catalog, f.options.Trust, f.options.Binding, request.Challenge, nil, nil, "0.1.0", request.Now)
			if err != nil {
				t.Fatal(err)
			}
			f.options.Binding = local
			state := contracts.LifecycleState{SchemaVersion: 1, Sequence: "1", Checkpoint: selected.Accepted.Checkpoint, CatalogFloor: selected.Floor, Packages: []contracts.PublishedPackage{}, Generations: []contracts.Generation{}, Attempts: []contracts.HostAttempt{}, Trash: []string{}}
			state.Checkpoint.BindingDigest = digest(encoded(local))
			state.PolicyEnvelope = base64.RawURLEncoding.EncodeToString(request.Policy)
			state.FreshnessEnvelope = base64.RawURLEncoding.EncodeToString(request.Freshness)
			state.CatalogEnvelope = base64.RawURLEncoding.EncodeToString(request.Catalog)
			if row.root {
				state.Checkpoint.RootVersion = "900"
				state.CatalogFloor.RootVersion = "900"
			}
			payload := encoded(state)
			frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
			frame = append(frame, payload...)
			sum := sha256.Sum256(payload)
			frame = append(frame, sum[:]...)
			if err := os.WriteFile(filepath.Join(f.root, "generations.log"), frame, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			m, err := Open(ctx, f.options)
			if err == nil {
				_ = m.Close()
				t.Fatal("accepted checksummed foreign authority")
			}
			if err.Error() != row.expected {
				t.Fatal("unexpected semantic replay rejection", err)
			}
			if f.requests.Load() != 0 {
				t.Fatal("invalid restored authority fetched an artifact")
			}
		})
	}
}

func TestInstalledTamperingCannotRestart(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	f := newFixture(t)
	m := openFixture(t, f)
	if err := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{"feature.one": "1.0.0"})); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.state.Packages {
		if p.Entry.Manifest.ID == "shared.base" {
			if err := os.WriteFile(filepath.Join(f.root, "package-"+p.Identity, "data", "base"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	m = openFixture(t, f)
	defer m.Close()
	if err := m.Reconcile(context.Background(), f.request(t, "2", map[string]string{"feature.one": "1.0.0"})); err == nil {
		t.Fatal("tampered installed inventory executed")
	}
	if len(m.children) != 0 || m.state.Checkpoint.Revision != "2" {
		t.Fatal("tamper failure lost authority or started child")
	}
}

func TestValidatedSnapshotIsCallerIndependent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	f := newFixture(t)
	m := openFixture(t, f)
	defer m.Close()
	request := f.request(t, "1", map[string]string{"feature.one": "1.0.0"})
	m.boundary = func(boundary string) {
		if boundary == "authority-flush" {
			for i := range request.Policy {
				request.Policy[i] = 0
			}
			for i := range request.Catalog {
				request.Catalog[i] = 0
			}
			for _, raw := range request.Attestations {
				for i := range raw {
					raw[i] = 0
				}
			}
		}
	}
	if err := m.Reconcile(context.Background(), request); err != nil {
		t.Fatal("caller mutation changed validated authority", err)
	}
	snapshot := m.Snapshot()
	snapshot.Active = "bad"
	snapshot.Packages[0].Entry.Manifest.ID = "changed"
	if m.state.Active == "bad" || m.state.Packages[0].Entry.Manifest.ID == "changed" {
		t.Fatal("caller snapshot changed owner state")
	}
}
