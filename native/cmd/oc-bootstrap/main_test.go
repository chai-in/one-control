package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableEmptySelectionCreatesNoFiles(t *testing.T) {
	root := t.TempDir()
	name := "oc-bootstrap"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(root, name)
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-ldflags=-s -w", "-o", binary, ".")
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, output)
	}
	cwd := t.TempDir()
	cmd = exec.Command(binary)
	cmd.Dir = cwd
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("run: %v %s", e, output)
	}
	var result struct {
		SelectedPackages    int    `json:"selectedPackages"`
		Mode                string `json:"mode"`
		AuthorityConfigured bool   `json:"authorityConfigured"`
	}
	if e = json.Unmarshal(output, &result); e != nil {
		t.Fatal(e)
	}
	if result.SelectedPackages != 0 || result.Mode != "empty-selection-foundation" || result.AuthorityConfigured {
		t.Fatal(string(output))
	}
	entries, e := os.ReadDir(cwd)
	if e != nil || len(entries) != 0 {
		t.Fatalf("created files: %v %v", entries, e)
	}
}
