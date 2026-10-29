//go:build onecontrol_lifecycle_fixture

package lifecycle

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/packages"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type crashConfig struct {
	Root, Observer, Origin, Boundary string
	Certificate                      []byte
	Keys                             map[string][]byte
	Catalog                          contracts.ModuleCatalog
	Attestations                     map[string][]byte
}

func TestLifecycleControllerHelper(t *testing.T) {
	path := os.Getenv("ONECONTROL_FIXTURE_CONTROLLER_CONFIG")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var c crashConfig
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	once.Do(func() {
		keys = map[string]*rsa.PrivateKey{}
		for role, der := range c.Keys {
			k, e := x509.ParsePKCS1PrivateKey(der)
			if e != nil {
				panic(e)
			}
			keys[role] = k
		}
	})
	cert, e := x509.ParseCertificate(c.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	d, e := packages.OpenLifecycleFixture(packages.Options{Origins: []string{c.Origin}, Roots: roots, Trust: trust(t), PublisherKeys: map[string][]string{"fixture.publisher": {"publisher-attestation-v1"}}, StagingRoot: c.Root})
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	f := &fixture{root: c.Root, observer: c.Observer, catalog: c.Catalog, attestations: c.Attestations}
	f.options = Options{Root: c.Root, Trust: trust(t), Binding: authority.Binding{DeviceID: "fixture-device", EnrollmentID: "fixture-enrollment", Platform: fixturePlatform(), Scope: contracts.Scope{Kind: "machine", MachineID: "fixture-device"}}, BootstrapVersion: "0.1.0", Delivery: d}
	m := openFixture(t, f)
	m.boundary = func(boundary string) {
		if boundary == c.Boundary {
			fmt.Println(boundary)
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	if c.Boundary == "trash-intent" || c.Boundary == "trash" {
		e = m.Collect(1000)
	} else {
		e = m.Reconcile(context.Background(), f.request(t, "1", map[string]string{"feature.one": "1.0.0"}))
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Fatal("crash boundary was not reached")
}

func TestLifecycleControllerDeathBoundaries(t *testing.T) {
	for _, boundary := range []string{"authority-flush", "publication-intent", "stage", "publication", "publication-receipt", "candidate-intent", "instance-intent", "process-creation", "ready", "active-commit", "health", "healthy-commit", "trash-intent", "trash"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			if strings.HasPrefix(boundary, "trash") {
				m := openFixture(t, f)
				if e := m.Reconcile(context.Background(), f.request(t, "1", map[string]string{"feature.one": "1.0.0", "feature.two": "1.0.0"})); e != nil {
					t.Fatal(e)
				}
				if e := m.Reconcile(context.Background(), f.request(t, "2", map[string]string{})); e != nil {
					t.Fatal(e)
				}
				if e := m.Close(); e != nil {
					t.Fatal(e)
				}
			}
			c := crashConfig{Root: f.root, Observer: f.observer, Origin: f.server.URL, Boundary: boundary, Certificate: f.server.Certificate().Raw, Keys: map[string][]byte{}, Catalog: f.catalog, Attestations: f.attestations}
			for role, k := range keys {
				c.Keys[role] = x509.MarshalPKCS1PrivateKey(k)
			}
			path := filepath.Join(t.TempDir(), "fixture-keys-and-input.json")
			if e := os.WriteFile(path, encoded(c), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleControllerHelper$")
			cmd.Env = append(os.Environ(), "ONECONTROL_FIXTURE_CONTROLLER_CONFIG="+path)
			out, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			event := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(out).ReadString('\n'); event <- strings.TrimSpace(line) }()
			select {
			case got := <-event:
				if got != boundary {
					t.Fatalf("controller boundary %q", got)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("controller boundary timeout")
			}
			retained := []syscall.Handle{}
			if boundary == "process-creation" || boundary == "ready" || boundary == "active-commit" || boundary == "health" || boundary == "healthy-commit" {
				deadline := time.Now().Add(3 * time.Second)
				for {
					entries, _ := os.ReadDir(f.observer)
					if len(entries) > 0 {
						for _, entry := range entries {
							raw, e := os.ReadFile(filepath.Join(f.observer, entry.Name()))
							if e != nil {
								t.Fatal(e)
							}
							var o struct {
								PID   uint32
								State string
							}
							if e = json.Unmarshal(raw, &o); e != nil {
								t.Fatal(e)
							}
							h, e := syscall.OpenProcess(0x100000|0x1000, false, o.PID)
							if e != nil {
								t.Fatal(e)
							}
							retained = append(retained, h)
							r, e := syscall.WaitForSingleObject(h, 0)
							if e != nil || r != syscall.WAIT_TIMEOUT {
								t.Fatal("fixture was not live", r, e)
							}
							if (boundary == "ready" || boundary == "active-commit") && o.State != "ready" {
								t.Fatal("candidate executed before activation", o.State)
							}
							t.Logf("before controller death host=%d state=%s retained live handle", o.PID, o.State)
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("no actual host observation")
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e = cmd.Wait(); e == nil {
				t.Fatal("killed controller succeeded")
			}
			for _, h := range retained {
				r, e := syscall.WaitForSingleObject(h, 5000)
				syscall.CloseHandle(h)
				if e != nil || r != 0 {
					t.Fatal("actual host survived controller death", r, e)
				}
			}
			m := openFixture(t, f)
			defer m.Close()
			if m.Snapshot() == nil {
				t.Fatal("accepted authority lost")
			}
			t.Logf("restart policy floor=%s catalog floor=%s unknown=%t", m.state.Checkpoint.Revision, m.state.CatalogFloor.Revision, m.unknown())
			if boundary == "instance-intent" || len(retained) > 0 {
				if !m.unknown() {
					t.Fatal("unproved restored custody accepted")
				}
				if e = m.Reconcile(context.Background(), f.request(t, "3", map[string]string{})); !errors.Is(e, ErrUnknown) {
					t.Fatal("uncertain recovered instance permitted activation", e)
				}
				if e = m.Collect(1000); !errors.Is(e, ErrUnknown) {
					t.Fatal("uncertain recovered instance permitted collection", e)
				}
				if m.state.Checkpoint.Revision != "3" || m.state.CatalogFloor.Revision != "2" {
					t.Fatal("blocked recovery lost authority floors")
				}
			} else if strings.HasPrefix(boundary, "trash") {
				if e = m.Collect(1000); e != nil {
					t.Fatal(e)
				}
				for _, p := range m.state.Packages {
					exists, e := f.delivery.HasPublished(approval(p), attestation(p))
					if e != nil || exists {
						t.Fatal("trash recovery left published bytes", e)
					}
				}
			} else if boundary == "publication" {
				if e = m.Reconcile(context.Background(), f.request(t, "2", map[string]string{})); e != nil {
					t.Fatal("disable after interrupted rename failed", e)
				}
				if e = m.Collect(1000); e != nil {
					t.Fatal("renamed package with intent receipt was not collected", e)
				}
				for _, p := range m.state.Packages {
					if exists, err := f.delivery.HasPublished(approval(p), attestation(p)); err != nil || exists {
						t.Fatal("interrupted publication left installed bytes", err)
					}
				}
			} else {
				if e = m.Reconcile(context.Background(), f.request(t, "2", map[string]string{"feature.one": "1.0.0"})); e != nil {
					t.Fatal("inert interrupted work failed verified reconciliation", e)
				}
				if len(m.children) != 1 || m.state.Active != m.state.Healthy {
					t.Fatal("inert recovery did not converge")
				}
			}
		})
	}
}
