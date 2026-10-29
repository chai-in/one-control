// Package packages verifies inert package bytes. A receipt never authorizes execution.
package packages

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
)

const publisherRole = "publisher-attestation.v1"

type Limits struct {
	ArchiveBytes, FileBytes, InflatedBytes int64
	Entries                                int
}

func defaultLimits() Limits { return Limits{16 << 20, 16 << 20, 32 << 20, 128} }

// Approval comes from the caller's already authorized catalog. It grants no execution rights.
type Approval struct {
	ID, Version, Platform, Publisher, Layout, URL, SHA256 string
	Size                                                  int64
}
type Options struct {
	Origins       []string
	Networks      map[string][]netip.Prefix
	Roots         *x509.CertPool
	Trust         authority.Trust
	PublisherKeys map[string][]string
	StagingRoot   string
	Timeout       time.Duration
	Limits        Limits
}
type Delivery struct {
	options  Options
	origins  map[string]bool
	loopback bool
	parent   *os.Root
}
type Receipt struct{ directory, id, version, platform, digest string }

func (r Receipt) StagingDirectory() string { return r.directory }
func (r Receipt) Identity() string         { return r.id + "@" + r.version + "/" + r.platform }
func (r Receipt) ArchiveDigest() string    { return r.digest }

func Open(o Options) (*Delivery, error) { return open(o, false) }
func open(o Options, loopback bool) (*Delivery, error) {
	var pathError error
	o.StagingRoot, pathError = filepath.Abs(o.StagingRoot)
	if pathError != nil {
		return nil, pathError
	}
	if o.Limits == (Limits{}) {
		o.Limits = defaultLimits()
	}
	if o.Limits.ArchiveBytes < 1 || o.Limits.ArchiveBytes > 64<<20 || o.Limits.FileBytes < 1 || o.Limits.FileBytes > 64<<20 || o.Limits.InflatedBytes < 1 || o.Limits.InflatedBytes > 128<<20 || o.Limits.Entries < 1 || o.Limits.Entries > 512 {
		return nil, errors.New("invalid_limits")
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute {
		return nil, errors.New("invalid_timeout")
	}
	origins := map[string]bool{}
	for _, raw := range o.Origins {
		u, e := checkedURL(raw)
		if e != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
			return nil, errors.New("invalid_origin")
		}
		origins[u.Scheme+"://"+u.Host] = true
	}
	if len(origins) == 0 || len(origins) > 32 {
		return nil, errors.New("invalid_origin")
	}
	// Snapshot caller-owned policy so later mutations cannot change this owner.
	o.Origins = nil
	networks := make(map[string][]netip.Prefix, len(o.Networks))
	for origin, prefixes := range o.Networks {
		if !origins[origin] || len(prefixes) > 32 {
			return nil, errors.New("invalid_artifact_network")
		}
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 32) || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
				return nil, errors.New("invalid_artifact_network")
			}
		}
		networks[origin] = append([]netip.Prefix(nil), prefixes...)
	}
	o.Networks = networks
	keys := map[string][]string{}
	for p, ids := range o.PublisherKeys {
		keys[p] = append([]string(nil), ids...)
	}
	o.PublisherKeys = keys
	o.Trust.Keys = append([]authority.Key(nil), o.Trust.Keys...)
	for i := range o.Trust.Keys {
		k := &o.Trust.Keys[i]
		if k.Public != nil && k.Public.N != nil {
			k.Public = &rsa.PublicKey{N: new(big.Int).Set(k.Public.N), E: k.Public.E}
		}
	}
	if o.Roots != nil {
		o.Roots = o.Roots.Clone()
	}
	parent, e := os.OpenRoot(o.StagingRoot)
	if e != nil {
		return nil, e
	}
	return &Delivery{o, origins, loopback, parent}, nil
}
func (d *Delivery) Close() error { return d.parent.Close() }
func checkedURL(raw string) (*url.URL, error) {
	b, _ := json.Marshal(contracts.Artifact{URL: raw, SHA256: strings.Repeat("0", 64), Size: 1})
	var v contracts.Artifact
	if _, e := contracts.Decode(b, "Artifact", &v); e != nil {
		return nil, errors.New("invalid_url")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return nil, errors.New("invalid_url")
	}
	return u, nil
}
func (d *Delivery) attest(a Approval, raw []byte, now int64) (contracts.PackageAttestation, error) {
	var p contracts.PackageAttestation
	payload, e := authority.Verify(raw, publisherRole, d.options.Trust, now)
	if e != nil {
		return p, e
	}
	if _, e = contracts.Decode(payload, "PackageAttestation", &p); e != nil {
		return p, e
	}
	var env contracts.Envelope
	_, _ = contracts.Decode(raw, "Envelope", &env)
	// Verify has already checked canonical encoding and the signature over these bytes.
	protected, _ := decodeProtected(env.Protected)
	allowed := false
	for _, id := range d.options.PublisherKeys[a.Publisher] {
		if protected.KeyID == id {
			allowed = true
		}
	}
	if !allowed || p.Publisher != a.Publisher {
		return p, errors.New("wrong_publisher")
	}
	if p.IssuedAt > now || p.ExpiresAt <= now || p.ExpiresAt <= p.IssuedAt {
		return p, errors.New("expired")
	}
	if p.ID != a.ID || p.Version != a.Version || p.Platform != a.Platform || p.Layout != a.Layout || p.ArchiveSHA256 != a.SHA256 || p.ArchiveSize != a.Size {
		return p, errors.New("wrong_package_binding")
	}
	if a.Size < 1 || a.Size > d.options.Limits.ArchiveBytes {
		return p, errors.New("archive_limit")
	}
	if e = inventory(p, d.options.Limits); e != nil {
		return p, e
	}
	return p, nil
}
func decodeProtected(s string) (contracts.Protected, error) {
	var p contracts.Protected
	b, e := decode64(s)
	if e != nil {
		return p, e
	}
	_, e = contracts.Decode(b, "Protected", &p)
	return p, e
}
func decode64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }
func (d *Delivery) fetch(ctx context.Context, a Approval) ([]byte, error) {
	u, e := checkedURL(a.URL)
	if e != nil {
		return nil, e
	}
	if !d.origins[u.Scheme+"://"+u.Host] {
		return nil, errors.New("unapproved_origin")
	}
	ctx, cancel := context.WithTimeout(ctx, d.options.Timeout)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if port == "0" {
		return nil, errors.New("invalid_port")
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if e != nil || len(ips) == 0 {
		return nil, errors.New("dns_rejected")
	}
	for _, ip := range ips {
		approvedNetwork := false
		for _, prefix := range d.options.Networks[u.Scheme+"://"+u.Host] {
			if prefix.Contains(ip.Unmap()) && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				approvedNetwork = true
				break
			}
		}
		if !publicIP(ip) && !approvedNetwork && !(d.loopback && ip.IsLoopback()) {
			return nil, errors.New("destination_rejected")
		}
	}
	dialer := &net.Dialer{Timeout: d.options.Timeout}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.options.Roots, ServerName: u.Hostname()}, ResponseHeaderTimeout: d.options.Timeout, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: d.options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_rejected") }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Type") != "application/zip" || resp.ContentLength != a.Size || len(resp.TransferEncoding) != 0 {
		return nil, errors.New("unsupported_response")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, a.Size+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != a.Size {
		return nil, errors.New("archive_length")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, errors.New("archive_hash")
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	// Timer callbacks can run after the body read completes.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	return b, nil
}
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "3fff::/20", "64:ff9b::/96"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}
func (d *Delivery) Stage(ctx context.Context, a Approval, attestation []byte, now int64) (Receipt, error) {
	p, e := d.attest(a, attestation, now)
	if e != nil {
		return Receipt{}, e
	}
	archive, e := d.fetch(ctx, a)
	if e != nil {
		return Receipt{}, e
	}
	files, e := validateZIP(archive, p, d.options.Limits)
	if e != nil {
		return Receipt{}, e
	}
	return d.stage(ctx, a, files)
}
func (d *Delivery) stage(ctx context.Context, a Approval, files []packageFile) (Receipt, error) {
	var e error
	if e = ctx.Err(); e != nil {
		return Receipt{}, e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return Receipt{}, e
	}
	directory := "uncommitted-" + hex.EncodeToString(nonce[:])
	if e = d.parent.Mkdir(directory, 0700); e != nil {
		return Receipt{}, e
	}
	createdRoot, e := d.parent.Lstat(directory)
	if e != nil || !createdRoot.IsDir() || createdRoot.Mode()&os.ModeSymlink != 0 {
		return Receipt{}, fmt.Errorf("%s: staged_directory", directory)
	}
	root, e := d.parent.OpenRoot(directory)
	if e != nil {
		return Receipt{}, fmt.Errorf("%s: %w", directory, e)
	}
	defer root.Close()
	openedRoot, e := root.Stat(".")
	if e != nil || !os.SameFile(createdRoot, openedRoot) {
		return Receipt{}, fmt.Errorf("%s: staged_directory_replaced", directory)
	}
	directories := map[string]*os.Root{"": root}
	defer func() {
		for name, dir := range directories {
			if name != "" {
				_ = dir.Close()
			}
		}
	}()
	for _, f := range files {
		if e = ctx.Err(); e != nil {
			return Receipt{}, fmt.Errorf("%s: %w", directory, e)
		}
		parts := strings.Split(f.name, "/")
		parent := root
		for i, segment := range parts[:len(parts)-1] {
			name := strings.Join(parts[:i+1], "/")
			child, exists := directories[name]
			if !exists {
				if e = parent.Mkdir(segment, 0700); e != nil {
					return Receipt{}, fmt.Errorf("%s: %w", directory, e)
				}
				created, err := parent.Lstat(segment)
				if err != nil || !created.IsDir() || created.Mode()&os.ModeSymlink != 0 {
					return Receipt{}, fmt.Errorf("%s: staged_directory", directory)
				}
				child, err = parent.OpenRoot(segment)
				if err != nil {
					return Receipt{}, fmt.Errorf("%s: %w", directory, err)
				}
				opened, err := child.Stat(".")
				if err != nil || !os.SameFile(created, opened) {
					child.Close()
					return Receipt{}, fmt.Errorf("%s: staged_directory_replaced", directory)
				}
				directories[name] = child
			}
			parent = child
		}
		base := parts[len(parts)-1]
		file, err := parent.OpenFile(base, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return Receipt{}, fmt.Errorf("%s: %w", directory, err)
		}
		_, err = file.Write(f.data)
		if err == nil {
			err = file.Sync()
		}
		if err != nil {
			_ = file.Close()
			return Receipt{}, fmt.Errorf("%s: %w", directory, err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(f.data)) {
			file.Close()
			return Receipt{}, fmt.Errorf("%s: staged_type", directory)
		}
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			file.Close()
			return Receipt{}, fmt.Errorf("%s: %w", directory, err)
		}
		actual, err := io.ReadAll(io.LimitReader(file, int64(len(f.data))+1))
		current, statErr := parent.Lstat(base)
		closeErr := file.Close()
		if err != nil || closeErr != nil || statErr != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 || len(actual) != len(f.data) || sha256.Sum256(actual) != sha256.Sum256(f.data) {
			return Receipt{}, fmt.Errorf("%s: staged_hash", directory)
		}
	}
	return Receipt{directory, a.ID, a.Version, a.Platform, a.SHA256}, nil
}
