//go:build onecontrol_lifecycle_fixture

package lifecycle

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func retainFixture(t *testing.T, f *fixture) string {
	t.Helper()
	parent := os.Getenv("ONE_CONTROL_LIFECYCLE_EVIDENCE")
	if parent == "" {
		return ""
	}
	if !filepath.IsAbs(parent) {
		t.Fatal("fixture evidence path must be absolute")
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "real-tls-")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	public := map[string]string{}
	for role, key := range keys {
		raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		public[role] = base64.RawURLEncoding.EncodeToString(raw)
	}
	write("public-keys.json", encoded(public))
	write("tls-certificate.der", f.server.Certificate().Raw)
	write("catalog-payload.json", encoded(f.catalog))
	for _, entry := range f.catalog.Entries {
		id := entry.Manifest.ID
		raw := f.archives["/"+id+".zip"]
		write(id+".zip", raw)
		write(id+"-attestation.json", f.attestations[id+"@1.0.0"])
		t.Logf("actual TLS fixture archive=%s bytes=%d sha256=%s", id, len(raw), digest(raw))
	}
	t.Logf("retained actual fixture bytes and public verification material in %s", directory)
	return directory
}

func TestRejectedAuthorityHasNoForwardEffects(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	f := newFixture(t)
	m := openFixture(t, f)
	defer m.Close()
	if err := m.Reconcile(context.Background(), f.request(t, "5", map[string]string{"feature.one": "1.0.0"})); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	requests := f.requests.Load()
	for _, row := range []struct {
		name, revision, catalog, expected string
		enabled                           map[string]string
	}{
		{"old-policy", "4", "2", "stale_revision", map[string]string{}},
		{"policy-equivocation", "5", "2", "equivocation", map[string]string{}},
		{"new-policy-old-catalog", "6", "1", "stale_revision", map[string]string{}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f.catalog.Revision = row.catalog
			request := f.request(t, row.revision, row.enabled)
			if err := m.Reconcile(context.Background(), request); err == nil || err.Error() != row.expected {
				t.Fatal("unauthorized change was accepted", err)
			}
			if !reflect.DeepEqual(before, m.Snapshot()) || f.requests.Load() != requests || len(m.children) != 1 {
				t.Fatal("rejected authority changed journal, network effects, or host ownership")
			}
		})
	}
}

func TestRuntimeArchitectureRejectsMismatchedBinding(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows platform binding boundary")
	}
	f := newFixture(t)
	if fixturePlatform() == "win-x64" {
		f.options.Binding.Platform = "win-arm64"
	} else {
		f.options.Binding.Platform = "win-x64"
	}
	m := openFixture(t, f)
	defer m.Close()
	if err := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{})); err == nil || err.Error() != "unsupported_platform" {
		t.Fatal("wrong native architecture was accepted", err)
	}
	if m.Snapshot() != nil || f.requests.Load() != 0 || len(m.children) != 0 {
		t.Fatal("wrong architecture caused authority or process effects")
	}
}

func TestCollectAbandonedAndExpiredPackages(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	for _, scenario := range []struct {
		name string
		now  int64
	}{
		{"abandoned-download", 1000},
		{"expired-quiescent", 8000},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newFixture(t)
			if scenario.name == "abandoned-download" {
				delete(f.archives, "/feature.one.zip")
			}
			m := openFixture(t, f)
			defer func() { _ = m.Close() }()
			err := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{"feature.one": "1.0.0"}))
			if scenario.name == "abandoned-download" {
				if err == nil || err.Error() != "unsupported_response" || len(m.state.Packages) != 2 {
					t.Fatal("actual missing TLS archive was not exercised", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err = m.Reconcile(context.Background(), f.request(t, "2", map[string]string{})); err != nil {
				t.Fatal(err)
			}
			if len(m.children) != 0 || m.unknown() {
				t.Fatal("cleanup did not establish quiescence")
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m = openFixture(t, f)
			if err = m.Collect(scenario.now); err != nil {
				t.Fatal("quiescent unused closure did not collect", err)
			}
			if err = m.Collect(scenario.now); err != nil {
				t.Fatal("repeated collection did not converge", err)
			}
			for _, p := range m.state.Packages {
				if exists, err := f.delivery.HasPublished(approval(p), attestation(p)); err != nil || exists {
					t.Fatal("unused package bytes remain", err)
				}
			}
			if len(m.state.Trash) != len(m.state.Packages) {
				t.Fatal("cleanup lost immutable package receipts")
			}
			t.Logf("collected at time=%d records=%d children=%d", scenario.now, len(m.state.Packages), len(m.children))
		})
	}
}

func TestExpiredPinnedBytesDoNotAuthorizeForwardUse(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	f := newFixture(t)
	m := openFixture(t, f)
	defer m.Close()
	if err := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{"feature.one": "1.0.0"})); err != nil {
		t.Fatal(err)
	}
	if err := m.Collect(8000); err != nil {
		t.Fatal("expired pinned bytes blocked harmless collection", err)
	}
	if len(m.state.Trash) != 0 || len(m.children) != 1 {
		t.Fatal("expired pin was deleted or live host ownership changed")
	}
	for _, p := range m.state.Packages {
		if err := f.delivery.VerifyPublished(approval(p), attestation(p), 8000); err == nil || err.Error() != "expired" {
			t.Fatal("cleanup granted current-time package reuse", err)
		}
		if p.Entry.Manifest.Kind == "feature" {
			if _, err := f.delivery.FixedExecutable(approval(p), attestation(p), 8000); err == nil || err.Error() != "expired" {
				t.Fatal("cleanup granted current-time launch", err)
			}
		}
	}
}
