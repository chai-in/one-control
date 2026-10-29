//go:build onecontrol_lifecycle_fixture

package lifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/packages"
	"onecontrol/native/internal/processhost"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var once sync.Once
var keys map[string]*rsa.PrivateKey
var hostBytes []byte

func material(t *testing.T) {
	t.Helper()
	once.Do(func() {
		keys = map[string]*rsa.PrivateKey{}
		for _, role := range []string{authority.PolicyRole, authority.FreshnessRole, authority.CatalogRole, "publisher-attestation.v1"} {
			k, e := rsa.GenerateKey(rand.Reader, 3072)
			if e != nil {
				panic(e)
			}
			keys[role] = k
		}
		if runtime.GOOS == "windows" {
			dir, e := os.MkdirTemp("", "oc-fixed-host-")
			if e != nil {
				panic(e)
			}
			defer os.RemoveAll(dir)
			p := filepath.Join(dir, "host.exe")
			out, e := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go.exe"), "build", "-trimpath", "-o", p, "./testdata/host").CombinedOutput()
			if e != nil {
				panic(fmt.Sprint(e, string(out)))
			}
			hostBytes, e = os.ReadFile(p)
			if e != nil {
				panic(e)
			}
		}
	})
}

func sign(t *testing.T, role string, payload any) []byte {
	t.Helper()
	material(t)
	p := encoded(payload)
	h := encoded(contracts.Protected{SchemaVersion: 1, Domain: role, Alg: "PS256", RootVersion: "1", KeyID: strings.ReplaceAll(role, ".", "-")})
	id := strings.ReplaceAll(role, ".", "-")
	sum := sha256.Sum256(authority.SigningBytes(id, h, p))
	sig, e := rsa.SignPSS(rand.Reader, keys[role], crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return encoded(contracts.Envelope{Protected: enc(h), Payload: enc(p), Signature: enc(sig)})
}

func trust(t *testing.T) authority.Trust {
	material(t)
	out := authority.Trust{RootVersion: 1, Epoch: 1}
	for role, k := range keys {
		out.Keys = append(out.Keys, authority.Key{ID: strings.ReplaceAll(role, ".", "-"), Role: role, Public: &k.PublicKey, NotBefore: 1, NotAfter: 10000})
	}
	return out
}

func zipBytes(files map[string][]byte) []byte {
	var b, c bytes.Buffer
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		data := files[name]
		start := b.Len()
		h := make([]byte, 30)
		binary.LittleEndian.PutUint32(h, 0x04034b50)
		binary.LittleEndian.PutUint16(h[4:], 20)
		binary.LittleEndian.PutUint32(h[14:], crc32.ChecksumIEEE(data))
		binary.LittleEndian.PutUint32(h[18:], uint32(len(data)))
		binary.LittleEndian.PutUint32(h[22:], uint32(len(data)))
		binary.LittleEndian.PutUint16(h[26:], uint16(len(name)))
		b.Write(h)
		b.WriteString(name)
		b.Write(data)
		ch := make([]byte, 46)
		binary.LittleEndian.PutUint32(ch, 0x02014b50)
		binary.LittleEndian.PutUint16(ch[4:], 20)
		copy(ch[6:28], h[4:26])
		binary.LittleEndian.PutUint16(ch[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(ch[42:], uint32(start))
		c.Write(ch)
		c.WriteString(name)
	}
	offset := b.Len()
	b.Write(c.Bytes())
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end, 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(len(names)))
	binary.LittleEndian.PutUint16(end[10:], uint16(len(names)))
	binary.LittleEndian.PutUint32(end[12:], uint32(c.Len()))
	binary.LittleEndian.PutUint32(end[16:], uint32(offset))
	b.Write(end)
	return b.Bytes()
}
func sortStrings(values []string) {
	for i := range values {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

func fixturePlatform() string {
	if runtime.GOOS == "windows" && runtime.GOARCH == "arm64" {
		return "win-arm64"
	}
	return "win-x64"
}

type fixture struct {
	root, observer string
	server         *httptest.Server
	delivery       *packages.Delivery
	options        Options
	catalog        contracts.ModuleCatalog
	attestations   map[string][]byte
	archives       map[string][]byte
	requests       atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	material(t)
	f := &fixture{root: t.TempDir(), observer: t.TempDir(), attestations: map[string][]byte{}, archives: map[string][]byte{}}
	platform := fixturePlatform()
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		b, ok := f.archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Write(b)
	}))
	t.Cleanup(f.server.Close)
	f.catalog = contracts.ModuleCatalog{SchemaVersion: 2, AuthorityEpoch: "1", Revision: "2", IssuedAt: 100, ExpiresAt: 8000, Entries: []contracts.CatalogEntry{}}
	for _, id := range []string{"shared.base", "feature.one", "feature.two"} {
		shared := id == "shared.base"
		layout, abi, kind := "native-host-v1", "one-control-host-v1", "feature"
		files := map[string][]byte{"data/observer": []byte(f.observer)}
		deps := map[string]string{"shared.base": "1.0.0"}
		if shared {
			layout, abi, kind = "passive-v1", "none", "shared"
			files = map[string][]byte{"data/base": []byte("shared exact bytes")}
			deps = map[string]string{}
		} else {
			files["bin/host.exe"] = hostBytes
			if runtime.GOOS != "windows" {
				files["bin/host.exe"] = []byte("not executed on this platform")
			}
		}
		archive := zipBytes(files)
		path := "/" + id + ".zip"
		f.archives[path] = archive
		p := contracts.PackageAttestation{SchemaVersion: 1, ID: id, Version: "1.0.0", Platform: platform, Publisher: "fixture.publisher", Layout: layout, ArchiveSHA256: digest(archive), ArchiveSize: int64(len(archive)), Files: []contracts.PackageFile{}, IssuedAt: 100, ExpiresAt: 8000}
		names := []string{}
		for name := range files {
			names = append(names, name)
		}
		sortStrings(names)
		for _, name := range names {
			data := files[name]
			p.Files = append(p.Files, contracts.PackageFile{Path: name, SHA256: digest(data), Size: int64(len(data))})
		}
		raw := sign(t, "publisher-attestation.v1", p)
		f.attestations[id+"@1.0.0"] = raw
		f.catalog.Entries = append(f.catalog.Entries, contracts.CatalogEntry{Manifest: contracts.Manifest{SchemaVersion: 1, ID: id, Version: "1.0.0", Kind: kind, MinimumBootstrap: "0.1.0", Permissions: []string{}, Dependencies: deps, Artifacts: map[string]contracts.Artifact{platform: {URL: f.server.URL + path, SHA256: p.ArchiveSHA256, Size: p.ArchiveSize}}}, Platforms: map[string]contracts.CatalogPlatform{platform: {Publisher: p.Publisher, Layout: layout, HostAbi: abi, Scope: "machine", AttestationSha256: digest(raw)}}})
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	var e error
	f.delivery, e = packages.OpenLifecycleFixture(packages.Options{Origins: []string{f.server.URL}, Roots: roots, Trust: trust(t), PublisherKeys: map[string][]string{"fixture.publisher": {"publisher-attestation-v1"}}, StagingRoot: f.root})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.delivery.Close() })
	f.options = Options{Root: f.root, Trust: trust(t), Binding: authority.Binding{DeviceID: "fixture-device", EnrollmentID: "fixture-enrollment", Platform: platform, Scope: contracts.Scope{Kind: "machine", MachineID: "fixture-device"}}, BootstrapVersion: "0.1.0", Delivery: f.delivery}
	return f
}

func (f *fixture) request(t *testing.T, revision string, enabled map[string]string) Request {
	t.Helper()
	challenge, e := authority.NewChallenge()
	if e != nil {
		t.Fatal(e)
	}
	p := contracts.Policy{SchemaVersion: 1, AuthorityEpoch: "1", Revision: revision, DeviceID: f.options.Binding.DeviceID, EnrollmentID: f.options.Binding.EnrollmentID, Platform: f.options.Binding.Platform, Scope: f.options.Binding.Scope, CatalogDigest: digest(encoded(f.catalog)), Enabled: enabled, Disabled: []string{}, AllowedPermissions: []string{}, IssuedAt: 100, ExpiresAt: 8000}
	fresh := contracts.Freshness{SchemaVersion: 1, AuthorityEpoch: "1", DeviceID: p.DeviceID, EnrollmentID: p.EnrollmentID, PolicyDigest: digest(encoded(p)), Nonce: challenge.Nonce(), IssuedAt: 1000, ExpiresAt: 1100}
	return Request{Policy: sign(t, authority.PolicyRole, p), Freshness: sign(t, authority.FreshnessRole, fresh), Catalog: sign(t, authority.CatalogRole, f.catalog), Challenge: challenge, Attestations: f.attestations, Now: 1000}
}

func openFixture(t *testing.T, f *fixture) *Manager {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, e := Open(ctx, f.options)
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func TestLifecycleRealTLS(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows containment required")
	}
	f := newFixture(t)
	evidence := retainFixture(t, f)
	m := openFixture(t, f)
	defer m.Close()
	ctx := context.Background()
	apply := func(rev string, enabled map[string]string) {
		t.Helper()
		request := f.request(t, rev, enabled)
		if evidence != "" {
			for name, raw := range map[string][]byte{"policy": request.Policy, "freshness": request.Freshness, "catalog": request.Catalog} {
				if e := os.WriteFile(filepath.Join(evidence, rev+"-"+name+".json"), raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
		if e := m.Reconcile(ctx, request); e != nil {
			t.Fatal(e)
		}
		s := m.Snapshot()
		if s.Active == "" || s.Active != s.Healthy || s.Candidate != "" {
			t.Fatal("generation not healthy", s)
		}
		for _, p := range s.Packages {
			if p.State != "published" {
				continue
			}
			collected := false
			for _, id := range s.Trash {
				collected = collected || id == p.Identity
			}
			if !collected {
				if e := f.delivery.VerifyPublished(approval(p), attestation(p), request.Now); e != nil {
					t.Fatal("actual published inventory differs", e)
				}
			}
		}
		t.Logf("revision=%s requests=%d children=%d packages=%d active=%s", rev, f.requests.Load(), len(m.children), len(s.Packages), s.Active)
	}
	apply("1", map[string]string{})
	if f.requests.Load() != 0 || len(m.children) != 0 {
		t.Fatal("empty selection had feature effects")
	}
	apply("2", map[string]string{"feature.one": "1.0.0"})
	if f.requests.Load() != 2 || len(m.children) != 1 {
		t.Fatal("one feature closure")
	}
	one := m.Snapshot().Active
	apply("3", map[string]string{"feature.one": "1.0.0", "feature.two": "1.0.0"})
	if f.requests.Load() != 3 || len(m.children) != 2 || len(m.Snapshot().Packages) != 3 {
		t.Fatal("shared dependency not deduplicated")
	}
	attempts := len(m.Snapshot().Attempts)
	apply("4", map[string]string{"feature.one": "1.0.0", "feature.two": "1.0.0"})
	if len(m.Snapshot().Attempts) != attempts || f.requests.Load() != 3 {
		t.Fatal("unchanged selection restarted or fetched")
	}
	apply("5", map[string]string{"feature.one": "1.0.0"})
	if m.Snapshot().Active != one || len(m.children) != 1 {
		t.Fatal("current-authority retained selection not reused")
	}
	if e := m.Collect(1000); e != nil {
		t.Fatal(e)
	}
	if len(m.Snapshot().Trash) != 1 {
		t.Fatal("inactive root not collected")
	}
	for _, p := range m.Snapshot().Packages {
		if p.Entry.Manifest.ID == "shared.base" {
			if e := f.delivery.VerifyPublished(approval(p), attestation(p), 1000); e != nil {
				t.Fatal("shared dependency collected", e)
			}
		}
	}
	apply("6", map[string]string{})
	if len(m.children) != 0 {
		t.Fatal("disabled hosts remain")
	}
	if e := m.Collect(1000); e != nil {
		t.Fatal(e)
	}
	if len(m.Snapshot().Trash) != 3 {
		t.Fatal("disabled closure not collected")
	}
	apply("7", map[string]string{"feature.one": "1.0.0"})
	if len(m.children) != 1 || f.requests.Load() != 5 {
		t.Fatal("collected selection did not download and activate")
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	m = openFixture(t, f)
	defer m.Close()
	apply("8", map[string]string{"feature.one": "1.0.0"})
	if len(m.children) != 1 {
		t.Fatal("closed restart returned empty live generation")
	}
}

func TestCatalogFloorIndependentOfPolicy(t *testing.T) {
	f := newFixture(t)
	first := f.request(t, "1", map[string]string{})
	a, e := authority.AcceptSelection(first.Policy, first.Freshness, first.Catalog, f.options.Trust, f.options.Binding, first.Challenge, nil, nil, "0.1.0", 1000)
	if e != nil {
		t.Fatal(e)
	}
	f.catalog.Revision = "1"
	old := f.request(t, "2", map[string]string{})
	_, e = authority.AcceptSelection(old.Policy, old.Freshness, old.Catalog, f.options.Trust, f.options.Binding, old.Challenge, &a.Accepted.Checkpoint, &a.Floor, "0.1.0", 1000)
	if e == nil || e.Error() != "stale_revision" {
		t.Fatal("newer policy lowered catalog floor", e)
	}
	if f.requests.Load() != 0 {
		t.Fatal("authority validation fetched artifacts")
	}
}

func TestLifecycleUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported adapter assertion is native Unix")
	}
	f := newFixture(t)
	m := openFixture(t, f)
	defer m.Close()
	if e := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{})); !errors.Is(e, processhost.ErrUnsupported) {
		t.Fatal(e)
	}
	if m.Snapshot() != nil || f.requests.Load() != 0 {
		t.Fatal("unsupported execution wrote authority or fetched")
	}
}
