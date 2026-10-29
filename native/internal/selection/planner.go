// Package selection ports the pure TypeScript exact-dependency planner. It owns
// no network, storage, execution or mutation authority.
package selection

import (
	"encoding/json"
	"errors"
	"onecontrol/native/internal/contracts"
	"sort"
	"strconv"
	"strings"
)

type Error struct {
	Code      string `json:"code"`
	ModuleKey string `json:"moduleKey"`
}

func (e *Error) Error() string      { return e.Code + ": " + e.ModuleKey }
func fail(code, key string) error   { return &Error{code, key} }
func key(id, version string) string { return id + "@" + version }
func sorted[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func compare(a, b string) int {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range 3 {
		x, _ := strconv.Atoi(aa[i])
		y, _ := strconv.Atoi(bb[i])
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func Resolve(data []byte) (contracts.Plan, error) {
	var in contracts.PlanInput
	orders, err := contracts.Decode(data, "PlanInput", &in)
	if err != nil {
		return contracts.Plan{}, err
	}
	empty := contracts.Plan{Packages: []contracts.Planned{}, Deactivate: []string{}, RemovalCandidates: []string{}}
	manifests := map[string]contracts.Manifest{}
	for _, m := range in.Catalog {
		k := key(m.ID, m.Version)
		if _, ok := manifests[k]; ok {
			return empty, fail("duplicate_manifest", k)
		}
		manifests[k] = m
	}
	installed := map[string]contracts.Installed{}
	installedKeys := []string{}
	dependencyOrder := map[string][]string{}
	for i, m := range in.Installed {
		k := key(m.ID, m.Version)
		if _, ok := installed[k]; ok {
			return empty, fail("duplicate_installed_module", k)
		}
		installed[k] = m
		installedKeys = append(installedKeys, k)
		dependencyOrder[k] = orders["/installed/"+strconv.Itoa(i)+"/dependencies"]
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var validate func(string) error
	validate = func(k string) error {
		if visiting[k] {
			return fail("installed_dependency_cycle", k)
		}
		if visited[k] {
			return nil
		}
		m, ok := installed[k]
		if !ok {
			return fail("missing_installed_dependency", k)
		}
		visiting[k] = true
		for _, id := range dependencyOrder[k] {
			if e := validate(key(id, m.Dependencies[id])); e != nil {
				return e
			}
		}
		delete(visiting, k)
		visited[k] = true
		return nil
	}
	for _, k := range installedKeys {
		if e := validate(k); e != nil {
			return empty, e
		}
	}
	retained := map[string]bool{}
	var retain func(string)
	retain = func(k string) {
		if retained[k] {
			return
		}
		retained[k] = true
		for id, v := range installed[k].Dependencies {
			retain(key(id, v))
		}
	}
	for k, m := range installed {
		if m.RollbackPinned != nil && *m.RollbackPinned {
			retain(k)
		}
	}
	permissions, disabled := map[string]bool{}, map[string]bool{}
	for _, p := range in.AllowedPermissions {
		permissions[p] = true
	}
	for _, id := range in.Disabled {
		disabled[id] = true
	}
	planned := map[string]*contracts.Planned{}
	sequence := []string{}
	visiting = map[string]bool{}
	var visit func(string, string) error
	visit = func(k, root string) error {
		if visiting[k] {
			return fail("dependency_cycle", k)
		}
		prior := planned[k]
		if prior != nil {
			for _, r := range prior.RequiredBy {
				if r == root {
					return nil
				}
			}
		}
		m, ok := manifests[k]
		if !ok {
			return fail("missing_manifest", k)
		}
		if disabled[m.ID] {
			return fail("module_disabled", k)
		}
		if compare(in.BootstrapVersion, m.MinimumBootstrap) < 0 {
			return fail("bootstrap_upgrade_required", k)
		}
		for _, p := range m.Permissions {
			if !permissions[p] {
				return fail("permission_not_granted", k)
			}
		}
		artifact, ok := m.Artifacts[in.Platform]
		if !ok {
			return fail("unsupported_platform", k)
		}
		visiting[k] = true
		for _, id := range sorted(m.Dependencies) {
			if e := visit(key(id, m.Dependencies[id]), root); e != nil {
				return e
			}
		}
		delete(visiting, k)
		if prior != nil {
			prior.RequiredBy = append(prior.RequiredBy, root)
		} else {
			current, exists := installed[k]
			planned[k] = &contracts.Planned{Key: k, Manifest: m, Artifact: artifact, RequiredBy: []string{root}, DownloadRequired: !exists || current.SHA256 != artifact.SHA256 || current.Size != artifact.Size}
			sequence = append(sequence, k)
		}
		return nil
	}
	for _, id := range sorted(in.Enabled) {
		k := key(id, in.Enabled[id])
		if m, ok := manifests[k]; ok && m.Kind == "shared" {
			return empty, fail("feature_root_required", k)
		}
		if e := visit(k, id); e != nil {
			return empty, e
		}
	}
	for _, k := range sequence {
		sort.Strings(planned[k].RequiredBy)
		empty.Packages = append(empty.Packages, *planned[k])
	}
	for k, m := range installed {
		if planned[k] == nil {
			if m.Active {
				empty.Deactivate = append(empty.Deactivate, k)
			}
			if !retained[k] {
				empty.RemovalCandidates = append(empty.RemovalCandidates, k)
			}
		}
	}
	sort.Strings(empty.Deactivate)
	sort.Strings(empty.RemovalCandidates)
	return empty, nil
}
func Outcome(data []byte) json.RawMessage {
	plan, err := Resolve(data)
	var result any
	if err == nil {
		result = map[string]any{"plan": plan}
	} else {
		var e *Error
		if errors.As(err, &e) {
			result = map[string]any{"error": e}
		} else {
			result = map[string]any{"error": map[string]string{"code": "invalid_wire"}}
		}
	}
	b, _ := json.Marshal(result)
	return b
}
