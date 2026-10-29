package packages

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
)

var fixtureOnce sync.Once
var fixtureKey *rsa.PrivateKey

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	fixtureOnce.Do(func() {
		var e error
		fixtureKey, e = rsa.GenerateKey(rand.Reader, 3072)
		if e != nil {
			panic(e)
		}
	})
	return fixtureKey
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type fixtureEntry struct {
	name    string
	data    []byte
	deflate bool
}

func fixtureZIP(entries []fixtureEntry) []byte {
	var body, central bytes.Buffer
	for _, f := range entries {
		compressed := f.data
		method := uint16(0)
		if f.deflate {
			var buf bytes.Buffer
			w, _ := flate.NewWriter(&buf, flate.BestCompression)
			_, _ = w.Write(f.data)
			_ = w.Close()
			compressed = buf.Bytes()
			method = 8
		}
		local := uint32(body.Len())
		name := []byte(f.name)
		crc := crc32.ChecksumIEEE(f.data)
		lh := make([]byte, 30)
		binary.LittleEndian.PutUint32(lh, 0x04034b50)
		binary.LittleEndian.PutUint16(lh[4:], 20)
		binary.LittleEndian.PutUint16(lh[8:], method)
		binary.LittleEndian.PutUint32(lh[14:], crc)
		binary.LittleEndian.PutUint32(lh[18:], uint32(len(compressed)))
		binary.LittleEndian.PutUint32(lh[22:], uint32(len(f.data)))
		binary.LittleEndian.PutUint16(lh[26:], uint16(len(name)))
		body.Write(lh)
		body.Write(name)
		body.Write(compressed)
		ch := make([]byte, 46)
		binary.LittleEndian.PutUint32(ch, 0x02014b50)
		binary.LittleEndian.PutUint16(ch[4:], 20)
		copy(ch[6:28], lh[4:26])
		binary.LittleEndian.PutUint16(ch[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(ch[42:], local)
		central.Write(ch)
		central.Write(name)
	}
	offset := uint32(body.Len())
	body.Write(central.Bytes())
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end, 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(len(entries)))
	binary.LittleEndian.PutUint16(end[10:], uint16(len(entries)))
	binary.LittleEndian.PutUint32(end[12:], uint32(central.Len()))
	binary.LittleEndian.PutUint32(end[16:], offset)
	body.Write(end)
	return body.Bytes()
}
func signed(t *testing.T, p contracts.PackageAttestation, keyID, domain string) []byte {
	t.Helper()
	payload, _ := json.Marshal(p)
	protected, _ := json.Marshal(contracts.Protected{SchemaVersion: 1, Domain: domain, Alg: "PS256", RootVersion: "1", KeyID: keyID})
	sum := sha256.Sum256(authority.SigningBytes(keyID, protected, payload))
	sig, e := rsa.SignPSS(rand.Reader, key(t), crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	raw, _ := json.Marshal(contracts.Envelope{Protected: enc(protected), Payload: enc(payload), Signature: enc(sig)})
	return raw
}
func attestation(entries []fixtureEntry, b []byte) contracts.PackageAttestation {
	p := contracts.PackageAttestation{SchemaVersion: 1, ID: "shared.payload", Version: "1.0.0", Platform: "win-x64", Publisher: "fixture.publisher", Layout: "passive-v1", ArchiveSHA256: hash(b), ArchiveSize: int64(len(b)), IssuedAt: 100, ExpiresAt: 200}
	for _, f := range entries {
		p.Files = append(p.Files, contracts.PackageFile{Path: f.name, SHA256: hash(f.data), Size: int64(len(f.data))})
	}
	return p
}
func approval(p contracts.PackageAttestation, uri string) Approval {
	return Approval{p.ID, p.Version, p.Platform, p.Publisher, p.Layout, uri, p.ArchiveSHA256, p.ArchiveSize}
}
func options(t *testing.T, s *httptest.Server) Options {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return Options{Origins: []string{s.URL}, Roots: roots, Trust: authority.Trust{RootVersion: 1, Epoch: 1, Keys: []authority.Key{{ID: "publisher", Role: publisherRole, Public: &key(t).PublicKey, NotBefore: 1, NotAfter: 1000}}}, PublisherKeys: map[string][]string{"fixture.publisher": {"publisher"}}, StagingRoot: t.TempDir(), Timeout: time.Second}
}
func server(t *testing.T, b []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("fixture request method=%s path=%s tls=%t", r.Method, r.URL.Path, r.TLS != nil)
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("compression requested")
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", fmtInt(len(b)))
		_, _ = w.Write(b)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(s.Close)
	return s
}
func fmtInt(n int) string { return fmt.Sprint(n) }
func TestRealHTTPSStagesPassiveAndFixedHost(t *testing.T) {
	for _, host := range []bool{false, true} {
		t.Run(fmt.Sprint(host), func(t *testing.T) {
			entries := []fixtureEntry{{"data/payload.txt", []byte("shared passive payload"), true}}
			if host {
				entries = append(entries, fixtureEntry{"bin/host.exe", []byte("inert fixture host bytes, never executed"), false})
			}
			b := fixtureZIP(entries)
			p := attestation(entries, b)
			if host {
				p.Layout = "native-host-v1"
				p.ID = "feature.fixture"
			}
			s := server(t, b)
			o := options(t, s)
			d, e := open(o, true)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			envelope := signed(t, p, "publisher", publisherRole)
			r, e := d.Stage(context.Background(), approval(p, s.URL+"/package"), envelope, 150)
			if e != nil {
				t.Fatal(e)
			}
			if r.Identity() != p.ID+"@1.0.0/win-x64" || r.ArchiveDigest() != hash(b) {
				t.Fatal("receipt identity")
			}
			for _, f := range entries {
				actual, e := os.ReadFile(filepath.Join(o.StagingRoot, r.StagingDirectory(), filepath.FromSlash(f.name)))
				if e != nil || !bytes.Equal(actual, f.data) {
					t.Fatalf("actual staged bytes %s %v", f.name, e)
				}
			}
			if evidence := os.Getenv("ONE_CONTROL_PACKAGE_EVIDENCE"); evidence != "" {
				name := "passive"
				if host {
					name = "native-host"
				}
				dir := filepath.Join(evidence, name)
				if e = os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				for file, data := range map[string][]byte{"package.zip": b, "attestation.json": envelope} {
					if e = os.WriteFile(filepath.Join(dir, file), data, 0600); e != nil {
						t.Fatal(e)
					}
				}
				publicKey, err := x509.MarshalPKIXPublicKey(&key(t).PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				vector, _ := json.Marshal(map[string]any{"publicKey": base64.StdEncoding.EncodeToString(publicKey), "envelope": json.RawMessage(envelope)})
				if err = os.WriteFile(filepath.Join(dir, "public-vector.json"), vector, 0600); err != nil {
					t.Fatal(err)
				}
				assertions, _ := json.MarshalIndent(map[string]any{"identity": r.Identity(), "archiveBytes": len(b), "archiveSha256": r.ArchiveDigest(), "actualStagedFiles": p.Files, "allStagedBytesCompared": true, "executed": false}, "", "  ")
				if e = os.WriteFile(filepath.Join(dir, "assertions.json"), assertions, 0600); e != nil {
					t.Fatal(e)
				}
			}
			t.Logf("verified inert staged files=%d archiveBytes=%d identity=%s", len(entries), len(b), r.Identity())
		})
	}
}
func TestAttestationNegatives(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	b := fixtureZIP(entries)
	base := attestation(entries, b)
	s := server(t, b)
	o := options(t, s)
	d, e := open(o, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	cases := map[string]func(*contracts.PackageAttestation, *Approval){"expired": func(p *contracts.PackageAttestation, _ *Approval) { p.ExpiresAt = 149 }, "future": func(p *contracts.PackageAttestation, _ *Approval) { p.IssuedAt = 151 }, "platform": func(p *contracts.PackageAttestation, _ *Approval) { p.Platform = "linux-x64" }, "identity": func(p *contracts.PackageAttestation, _ *Approval) { p.ID = "other" }, "version": func(p *contracts.PackageAttestation, _ *Approval) { p.Version = "2.0.0" }, "publisher": func(p *contracts.PackageAttestation, _ *Approval) { p.Publisher = "other" }, "binding-hash": func(p *contracts.PackageAttestation, _ *Approval) { p.ArchiveSHA256 = strings.Repeat("0", 64) }, "binding-length": func(p *contracts.PackageAttestation, _ *Approval) { p.ArchiveSize++ }, "inventory-hash": func(p *contracts.PackageAttestation, _ *Approval) {
		p.Files = []contracts.PackageFile{{Path: "data/x", SHA256: strings.Repeat("0", 64), Size: 7}}
	}, "inventory-extra": func(p *contracts.PackageAttestation, _ *Approval) {
		p.Files = []contracts.PackageFile{{Path: "data/other", SHA256: hash([]byte("payload")), Size: 7}}
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			a := approval(base, s.URL)
			mutate(&p, &a)
			if _, e := d.Stage(context.Background(), a, signed(t, p, "publisher", publisherRole), 150); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, tc := range []struct{ name, keyID, role string }{{"wrong-signer", "unknown", publisherRole}, {"wrong-role", "publisher", "module-catalog.v2"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := d.Stage(context.Background(), approval(base, s.URL), signed(t, base, tc.keyID, tc.role), 150); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	raw := signed(t, base, "publisher", publisherRole)
	var env contracts.Envelope
	_ = json.Unmarshal(raw, &env)
	signature, _ := base64.RawURLEncoding.DecodeString(env.Signature)
	signature[0] ^= 1
	env.Signature = base64.RawURLEncoding.EncodeToString(signature)
	raw, _ = json.Marshal(env)
	if _, e := d.Stage(context.Background(), approval(base, s.URL), raw, 150); e == nil {
		t.Fatal("tampered signature accepted")
	}
	o.PublisherKeys = map[string][]string{"fixture.publisher": {"different-key"}}
	other, e := open(o, true)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.Stage(context.Background(), approval(base, s.URL), signed(t, base, "publisher", publisherRole), 150); e == nil {
		t.Fatal("catalog approval substituted for publisher binding")
	}
}
func TestTransportBoundaries(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	b := fixtureZIP(entries)
	p := attestation(entries, b)
	sig := signed(t, p, "publisher", publisherRole)
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		alter      func(*Options)
		production bool
	}{
		{name: "redirect", handler: func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.com/", 302) }},
		{name: "untrusted-tls", alter: func(o *Options) { o.Roots = x509.NewCertPool() }},
		{name: "production-loopback", production: true},
		{name: "unapproved-origin", alter: func(o *Options) { o.Origins = []string{"https://example.com"} }},
		{name: "compressed-response", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(b)
		}},
		{name: "oversized", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmtInt(len(b)+1))
			_, _ = w.Write(append(b, 0))
		}},
		{name: "truncated", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmtInt(len(b)))
			_, _ = w.Write(b[:len(b)-1])
		}},
		{name: "hash", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			bad := append([]byte(nil), b...)
			bad[40] ^= 1
			_, _ = w.Write(bad)
		}},
		{name: "slow-body", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmtInt(len(b)))
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(250 * time.Millisecond):
			}
			_, _ = w.Write(b)
		}, alter: func(o *Options) { o.Timeout = 30 * time.Millisecond }},
		{name: "chunked", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/zip")
			w.(http.Flusher).Flush()
			_, _ = w.Write(b)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/zip")
					_, _ = w.Write(b)
				}
			}
			s := httptest.NewTLSServer(handler)
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			defer s.Close()
			o := options(t, s)
			if tc.alter != nil {
				tc.alter(&o)
			}
			d, e := open(o, !tc.production)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			if _, e = d.Stage(context.Background(), approval(p, s.URL), sig, 150); e == nil {
				t.Fatal("accepted")
			}
			entries, e := os.ReadDir(o.StagingRoot)
			if e != nil || len(entries) != 0 {
				t.Fatal("transport failure staged bytes")
			}
		})
	}
}
func TestZIPMalformations(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	original := fixtureZIP(entries)
	p := attestation(entries, original)
	central := int(u32(original, len(original)-6))
	changes := map[string]func([]byte) []byte{
		"trailing": func(b []byte) []byte { return append(b, 0) }, "prefix": func(b []byte) []byte { return append([]byte{0}, b...) }, "local-mismatch": func(b []byte) []byte { b[14] ^= 1; return b }, "overlap": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[central+42:], 1); return b }, "encrypted": func(b []byte) []byte { b[central+8] = 1; return b }, "descriptor": func(b []byte) []byte { b[central+8] = 8; return b }, "symlink": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[central+38:], 0xa1ff0000); return b }, "extra": func(b []byte) []byte { b[central+30] = 1; return b }, "comment": func(b []byte) []byte { b[len(b)-2] = 1; return b }, "multipart": func(b []byte) []byte { b[len(b)-18] = 1; return b }, "zip64": func(b []byte) []byte { b[central+6] = 45; return b }, "crc": func(b []byte) []byte { b[localDataOffset(b)] ^= 1; return b }, "directory": func(b []byte) []byte { b[central+38] = 16; return b }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b := change(append([]byte(nil), original...))
			if _, e := validateZIP(b, p, defaultLimits()); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, name := range []string{"../x", "/x", "C:/x", "\\\\server\\x", "data\\x", "data/CON.txt", "data/x.", "data/x ", "data/é", "data/a:b", "data/./x", "data//x", "data/COM1.txt", "data/x\x00"} {
		t.Run(name, func(t *testing.T) {
			entries := []fixtureEntry{{name, []byte("x"), false}}
			p := attestation(entries, fixtureZIP(entries))
			if e := inventory(p, defaultLimits()); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, names := range [][]string{{"data/X", "data/x"}, {"data/x", "data/x"}, {"data/x", "data/x/y"}, {"data/A/x", "data/a/y"}} {
		entries := []fixtureEntry{{names[0], []byte("a"), false}, {names[1], []byte("b"), false}}
		if e := inventory(attestation(entries, fixtureZIP(entries)), defaultLimits()); e == nil {
			t.Fatal("collision accepted")
		}
	}
	bomb := []fixtureEntry{{"data/bomb", bytes.Repeat([]byte("x"), 100000), true}}
	bombZIP := fixtureZIP(bomb)
	if _, e := validateZIP(bombZIP, attestation(bomb, bombZIP), defaultLimits()); e == nil {
		t.Fatal("bomb accepted")
	}
	limits := defaultLimits()
	limits.InflatedBytes = 3
	if _, e := validateZIP(original, p, limits); e == nil {
		t.Fatal("inflation ceiling ignored")
	}
}
func localDataOffset(b []byte) int { return 30 + int(u16(b, 26)) }
func TestConcurrentAndInterruptedStaging(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	b := fixtureZIP(entries)
	p := attestation(entries, b)
	s := server(t, b)
	o := options(t, s)
	d, e := open(o, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	sig := signed(t, p, "publisher", publisherRole)
	a := approval(p, s.URL)
	const n = 8
	var group sync.WaitGroup
	receipts := make(chan Receipt, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := d.Stage(context.Background(), a, sig, 150)
			if e != nil {
				errs <- e
			} else {
				receipts <- r
			}
		}()
	}
	group.Wait()
	close(receipts)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for r := range receipts {
		if seen[r.directory] {
			t.Fatal("concurrent replacement")
		}
		seen[r.directory] = true
	}
	if len(seen) != n {
		t.Fatal("missing stages")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := d.Stage(ctx, a, sig, 150); e == nil {
		t.Fatal("cancelled operation accepted")
	}
	actual, _ := os.ReadDir(o.StagingRoot)
	if len(actual) != n {
		t.Fatal("interrupted download staged files")
	}
}
func TestDestinationAndURLRestrictions(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.1.1", "::1", "::ffff:127.0.0.1", "2001:db8::1", "224.0.0.1"} {
		if publicIP(netip.MustParseAddr(s)) {
			t.Errorf("allowed %s", s)
		}
	}
	for _, uri := range []string{"http://example.com", "https://user:pass@example.com/a", "https://example.com/a#fragment", "https://example.com/a\\x", "https://example.com/%xx"} {
		if _, e := checkedURL(uri); e == nil {
			t.Errorf("allowed %s", uri)
		}
	}
}

func TestPartialStagingCannotPublishOrOverwrite(t *testing.T) {
	s := server(t, []byte("unused"))
	o := options(t, s)
	d, e := open(o, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a := Approval{ID: "shared.payload", Version: "1.0.0", Platform: "win-x64", SHA256: hash([]byte("archive"))}
	first := packageFile{"data/x", []byte("first bytes")}
	r, e := d.stage(context.Background(), a, []packageFile{first, {"data/x", []byte("replacement")}})
	if e == nil || r.directory != "" {
		t.Fatal("partial stage returned receipt")
	}
	dirs, err := os.ReadDir(o.StagingRoot)
	if err != nil || len(dirs) != 1 || !strings.HasPrefix(dirs[0].Name(), "uncommitted-") || !strings.Contains(e.Error(), dirs[0].Name()) {
		t.Fatalf("unidentifiable stage %v %v", dirs, err)
	}
	actual, err := os.ReadFile(filepath.Join(o.StagingRoot, dirs[0].Name(), "data", "x"))
	if err != nil || !bytes.Equal(actual, first.data) {
		t.Fatal("exclusive create overwrote existing bytes")
	}
	t.Logf("interrupted stage retained uncommitted directory=%s actualBytes=%d receipt=false", dirs[0].Name(), len(actual))
}

func TestZIPTruncationAndMultipleEntryOverlap(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("one"), false}, {"data/y", []byte("two"), false}}
	b := fixtureZIP(entries)
	p := attestation(entries, b)
	for i := 0; i < len(b); i++ {
		if _, e := validateZIP(b[:i], p, defaultLimits()); e == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	central := int(u32(b, len(b)-6))
	second := central + 46 + len(entries[0].name)
	binary.LittleEndian.PutUint32(b[second+42:], 0)
	if _, e := validateZIP(b, p, defaultLimits()); e == nil {
		t.Fatal("overlapping local entries accepted")
	}
}

func TestPackageWireCrossLanguage(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	p := attestation(entries, fixtureZIP(entries))
	raw, _ := json.Marshal(p)
	node, e := exec.LookPath("node")
	if e != nil {
		t.Fatal("Node is required for the wire interoperability check")
	}
	cmd := exec.Command(node, "--input-type=module", "-e", `import { readFileSync } from "node:fs"; import { parseWire } from "../../../packages/module-contracts/src/validate.mjs"; process.stdout.write(JSON.stringify(parseWire("PackageAttestation",readFileSync(0))));`)
	cmd.Stdin = bytes.NewReader(raw)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("Node wire parser %v %s", e, out)
	}
	var actual contracts.PackageAttestation
	if _, e = contracts.Decode(out, "PackageAttestation", &actual); e != nil {
		t.Fatal(e)
	}
	got, _ := json.Marshal(actual)
	if !bytes.Equal(raw, got) {
		t.Fatal("cross-language attestation changed")
	}
}
