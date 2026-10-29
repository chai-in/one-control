package authority

import (
	"encoding/json"
	"onecontrol/native/internal/contracts"
	"strings"
	"testing"
)

func TestCatalogFloorTransitions(t *testing.T) {
	prior := contracts.CatalogFloor{RootVersion: "2", AuthorityEpoch: "4", Revision: "20", Digest: strings.Repeat("a", 64)}
	for _, row := range []struct {
		name    string
		next    contracts.CatalogFloor
		allowed bool
	}{
		{"unchanged", prior, true},
		{"newer", contracts.CatalogFloor{RootVersion: "2", AuthorityEpoch: "4", Revision: "21", Digest: strings.Repeat("b", 64)}, true},
		{"revision-rollback", contracts.CatalogFloor{RootVersion: "2", AuthorityEpoch: "4", Revision: "19", Digest: prior.Digest}, false},
		{"equivocation", contracts.CatalogFloor{RootVersion: "2", AuthorityEpoch: "4", Revision: "20", Digest: strings.Repeat("b", 64)}, false},
		{"unrooted-epoch", contracts.CatalogFloor{RootVersion: "2", AuthorityEpoch: "5", Revision: "1", Digest: prior.Digest}, false},
		{"rooted-epoch", contracts.CatalogFloor{RootVersion: "3", AuthorityEpoch: "5", Revision: "1", Digest: prior.Digest}, true},
		{"root-rollback", contracts.CatalogFloor{RootVersion: "1", AuthorityEpoch: "4", Revision: "21", Digest: prior.Digest}, false},
		{"epoch-rollback", contracts.CatalogFloor{RootVersion: "3", AuthorityEpoch: "3", Revision: "100", Digest: prior.Digest}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := AdvanceCatalog(&prior, row.next); (err == nil) != row.allowed {
				t.Fatal(err)
			}
		})
	}
}

func TestCatalogShapeAndDependencyBoundary(t *testing.T) {
	base := contracts.ModuleCatalog{SchemaVersion: 2, AuthorityEpoch: "1", Revision: "1", IssuedAt: 100, ExpiresAt: 200, Entries: []contracts.CatalogEntry{{Manifest: contracts.Manifest{SchemaVersion: 1, ID: "shared.base", Version: "1.0.0", Kind: "shared", MinimumBootstrap: "0.1.0", Permissions: []string{}, Dependencies: map[string]string{}, Artifacts: map[string]contracts.Artifact{"win-x64": {URL: "https://artifacts.example/base.zip", SHA256: strings.Repeat("a", 64), Size: 1}}}, Platforms: map[string]contracts.CatalogPlatform{"win-x64": {Publisher: "publisher", Layout: "passive-v1", HostAbi: "none", Scope: "machine", AttestationSha256: strings.Repeat("b", 64)}}}}}
	if err := ValidateCatalog(base); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		mutate func(*contracts.ModuleCatalog)
	}{
		{"duplicate", func(c *contracts.ModuleCatalog) { c.Entries = append(c.Entries, c.Entries[0]) }},
		{"incomplete-metadata", func(c *contracts.ModuleCatalog) { delete(c.Entries[0].Platforms, "win-x64") }},
		{"extra-metadata", func(c *contracts.ModuleCatalog) {
			c.Entries[0].Platforms["osx-arm64"] = c.Entries[0].Platforms["win-x64"]
		}},
		{"shared-executable", func(c *contracts.ModuleCatalog) {
			m := c.Entries[0].Platforms["win-x64"]
			m.Layout = "native-host-v1"
			m.HostAbi = "one-control-host-v1"
			c.Entries[0].Platforms["win-x64"] = m
		}},
		{"missing-dependency", func(c *contracts.ModuleCatalog) { c.Entries[0].Manifest.Dependencies["missing"] = "1.0.0" }},
		{"dependency-cycle", func(c *contracts.ModuleCatalog) { c.Entries[0].Manifest.Dependencies["shared.base"] = "1.0.0" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var c contracts.ModuleCatalog
			json.Unmarshal(raw, &c)
			row.mutate(&c)
			if err := ValidateCatalog(c); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}
