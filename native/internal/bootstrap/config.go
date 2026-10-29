// Package bootstrap connects installation custody with native module owners.
package bootstrap

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/protectedstore"
)

const Version = "0.1.0"

type PublicKey struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	PEM       string `json:"pem"`
	NotBefore int64  `json:"notBefore"`
	NotAfter  int64  `json:"notAfter"`
}

type Config struct {
	SchemaVersion    int                 `json:"schemaVersion"`
	Origin           string              `json:"origin"`
	DeviceID         string              `json:"deviceId"`
	MachineID        string              `json:"machineId"`
	Platform         string              `json:"platform"`
	RootVersion      string              `json:"rootVersion"`
	AuthorityEpoch   string              `json:"authorityEpoch"`
	Keys             []PublicKey         `json:"keys"`
	Publishers       map[string][]string `json:"publishers"`
	ArtifactOrigins  []string            `json:"artifactOrigins"`
	ArtifactNetworks map[string][]string `json:"artifactNetworks,omitempty"`
	TLSRootsPEM      string              `json:"tlsRootsPem,omitempty"`
	ReconcileSeconds int                 `json:"reconcileSeconds"`
	InventorySeconds int                 `json:"inventorySeconds"`
}

type Installation struct {
	Config   Config
	Trust    authority.Trust
	TLSRoots *x509.CertPool
	Networks map[string][]netip.Prefix
	Root     string
	Digest   string
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid_installation_json")
	}
	return nil
}

func Platform() string {
	return map[string]string{"windows": "win", "darwin": "osx", "linux": "linux"}[runtime.GOOS] + "-" + map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
}

func Load(path string) (*Installation, error) {
	raw, err := protectedstore.Read(path, 1<<20)
	if err != nil {
		return nil, err
	}
	var config Config
	if err = strictJSON(raw, &config); err != nil {
		return nil, err
	}
	if config.SchemaVersion != 1 || config.DeviceID == "" || config.MachineID == "" || config.Platform != Platform() || config.ReconcileSeconds < 15 || config.ReconcileSeconds > 60 || config.InventorySeconds < 60 || config.InventorySeconds > 86400 {
		return nil, errors.New("invalid_installation_configuration")
	}
	machine, err := MachineID()
	if err != nil {
		return nil, err
	}
	if config.MachineID != machine {
		return nil, errors.New("installation_machine_mismatch")
	}
	rootVersion, err := strconv.ParseUint(config.RootVersion, 10, 64)
	if err != nil || rootVersion == 0 || strconv.FormatUint(rootVersion, 10) != config.RootVersion {
		return nil, errors.New("invalid_trust_version")
	}
	epoch, err := strconv.ParseUint(config.AuthorityEpoch, 10, 64)
	if err != nil || epoch == 0 || strconv.FormatUint(epoch, 10) != config.AuthorityEpoch {
		return nil, errors.New("invalid_authority_epoch")
	}
	trust := authority.Trust{RootVersion: rootVersion, Epoch: epoch}
	seen := map[string]bool{}
	material := map[string]bool{}
	roles := map[string]bool{}
	if len(config.Keys) < 3 || len(config.Keys) > 32 {
		return nil, errors.New("invalid_installation_keys")
	}
	for _, entry := range config.Keys {
		block, rest := pem.Decode([]byte(entry.PEM))
		if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("invalid_installation_key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid_installation_key")
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 3072 || key.N.BitLen() > 8192 || key.E != 65537 || entry.ID == "" || entry.NotBefore <= 0 || entry.NotAfter <= entry.NotBefore || seen[entry.ID] || material[key.N.String()] {
			return nil, errors.New("invalid_installation_key")
		}
		switch entry.Role {
		case authority.CatalogRole, authority.PolicyRole, authority.FreshnessRole, "publisher-attestation.v1":
		default:
			return nil, errors.New("invalid_installation_key_role")
		}
		seen[entry.ID], material[key.N.String()], roles[entry.Role] = true, true, true
		trust.Keys = append(trust.Keys, authority.Key{ID: entry.ID, Role: entry.Role, Public: key, NotBefore: entry.NotBefore, NotAfter: entry.NotAfter})
	}
	if !roles[authority.CatalogRole] || !roles[authority.PolicyRole] || !roles[authority.FreshnessRole] {
		return nil, errors.New("installation_signing_roles_missing")
	}
	var roots *x509.CertPool
	if config.TLSRootsPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(config.TLSRootsPEM)) {
			return nil, errors.New("invalid_installation_tls_roots")
		}
	}
	networks := map[string][]netip.Prefix{}
	for origin, values := range config.ArtifactNetworks {
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, errors.New("invalid_artifact_network")
			}
			networks[origin] = append(networks[origin], prefix)
		}
	}
	digest := sha256.Sum256(raw)
	return &Installation{Config: config, Trust: trust, TLSRoots: roots, Networks: networks, Root: filepath.Dir(path), Digest: hex.EncodeToString(digest[:])}, nil
}
