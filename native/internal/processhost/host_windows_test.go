package processhost

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type observation struct {
	HostPID         uint32   `json:"hostPID"`
	LeafPID         uint32   `json:"leafPID"`
	Environment     []string `json:"environment"`
	InJobAtEntry    bool     `json:"inJobAtEntry"`
	BreakawayDenied bool     `json:"breakawayDenied"`
	DecoyExcluded   bool     `json:"decoyExcluded"`
}

func configFor(exe string) Config {
	return Config{Executable: exe, Instance: strings.Repeat("b", 64), ReadinessTimeout: 3 * time.Second, OperationTimeout: time.Second, StopTimeout: 500 * time.Millisecond}
}

func readObservation(t *testing.T, exe string) observation {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o observation
	if err = json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	if !o.InJobAtEntry || !o.BreakawayDenied || !o.DecoyExcluded || !reflect.DeepEqual(o.Environment, []string{"SystemRoot"}) {
		t.Fatalf("unsafe fixture entry: %s", b)
	}
	t.Log(string(b))
	return o
}

func retain(t *testing.T, pid uint32, job syscall.Handle) syscall.Handle {
	t.Helper()
	h, err := syscall.OpenProcess(0x100000|0x1000, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.CloseHandle(h) })
	if job != 0 {
		var member int32
		r, _, err := inJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&member)))
		if err = checked(r, err, "IsProcessInJob(test retained handle)"); err != nil || member == 0 {
			t.Fatalf("process outside exact job: %v", err)
		}
	}
	result, err := syscall.WaitForSingleObject(h, 0)
	if err != nil || result != 258 {
		t.Fatalf("process not live before teardown: %d %v", result, err)
	}
	return h
}

func assertExited(t *testing.T, h syscall.Handle) {
	t.Helper()
	r, err := syscall.WaitForSingleObject(h, 5000)
	if err != nil || r != 0 {
		t.Fatalf("owned process did not exit: %d %v", r, err)
	}
	var code uint32
	if err = syscall.GetExitCodeProcess(h, &code); err != nil || code == 259 {
		t.Fatalf("owned process still active: %d %v", code, err)
	}
	t.Logf("retained process signaled exit, code %d", code)
}

func installDecoy(t *testing.T, dir string) {
	t.Helper()
	name := "Local\\OneControlHostTest-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	h, _, err := kernel.NewProc("CreateEventW").Call(uintptr(unsafe.Pointer(&sa)), 1, 0, uintptr(unsafe.Pointer(n)))
	if err = checked(h, err, "CreateEventW(test decoy)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.CloseHandle(syscall.Handle(h)) })
	b, _ := json.Marshal(struct {
		Handle uintptr
		Name   string
	}{h, name})
	if err = os.WriteFile(filepath.Join(dir, "decoy.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerProcess(t *testing.T) {
	if os.Getenv("ONECONTROL_HOST_OWNER_HELPER") != "1" {
		return
	}
	exe := os.Getenv("ONECONTROL_HOST_FIXTURE")
	c, err := Start(configFor(exe))
	if err != nil {
		fmt.Println(err)
		os.Exit(3)
	}
	if err = c.AwaitReady(); err != nil {
		fmt.Println(err)
		os.Exit(3)
	}
	parentPID, err := strconv.ParseUint(os.Getenv("ONECONTROL_HOST_OBSERVER"), 10, 32)
	if err != nil {
		os.Exit(3)
	}
	parent, err := syscall.OpenProcess(0x40, false, uint32(parentPID))
	if err != nil {
		os.Exit(3)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		os.Exit(3)
	}
	var query syscall.Handle
	if err = syscall.DuplicateHandle(current, c.process.(*windowsProcess).job, parent, &query, 4, false, 0); err != nil {
		os.Exit(3)
	}
	syscall.CloseHandle(parent)
	fmt.Println(uintptr(query))
	for {
		time.Sleep(time.Hour)
	}
}

func TestWindowsOwnership(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "fixture.exe")
	goexe := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	if output, err := exec.Command(goexe, "build", "-trimpath", "-o", base, "./testdata/host").CombinedOutput(); err != nil {
		t.Fatalf("fixture build %v %s", err, output)
	}
	bytes, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	fixture := func(t *testing.T, mode string) string {
		p := filepath.Join(t.TempDir(), mode+".exe")
		if err := os.WriteFile(p, bytes, 0700); err != nil {
			t.Fatal(err)
		}
		installDecoy(t, filepath.Dir(p))
		return p
	}
	t.Setenv("ONECONTROL_AGENT_SECRET", "must-not-be-inherited")
	t.Run("atomically-assigned-while-suspended", func(t *testing.T) {
		exe := fixture(t, "normal")
		config := configFor(exe)
		p, err := createSuspended(config)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if p.pi.Process != 0 {
				p.abort()
			}
		}()
		time.Sleep(50 * time.Millisecond)
		if _, err = os.Stat(filepath.Join(filepath.Dir(exe), "observation.json")); !os.IsNotExist(err) {
			t.Fatalf("suspended host executed: %v", err)
		}
		var member int32
		r, _, err := inJob.Call(uintptr(p.pi.Process), uintptr(p.job), uintptr(unsafe.Pointer(&member)))
		if err = checked(r, err, "IsProcessInJob(before resume)"); err != nil || member != 1 {
			t.Fatalf("unexpected initial membership: %v", err)
		}
		if err = p.verifyAndResume(); err != nil {
			t.Fatal(err)
		}
		c := &Child{config: config, state: Candidate, process: p}
		if err = c.AwaitReady(); err != nil {
			t.Fatal(err)
		}
		readObservation(t, exe)
		if _, err = c.Stop(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("membership-query-failure-never-resumes", func(t *testing.T) {
		exe := fixture(t, "normal")
		p, err := createSuspended(configFor(exe))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if p.pi.Process != 0 {
				p.abort()
			}
		}()
		original := p.job
		current, err := syscall.GetCurrentProcess()
		if err != nil {
			t.Fatal(err)
		}
		var limited syscall.Handle
		if err = syscall.DuplicateHandle(current, original, current, &limited, 8, false, 0); err != nil {
			t.Fatal(err)
		}
		p.job = limited
		defer syscall.CloseHandle(limited)
		host := retain(t, p.pi.ProcessId, 0)
		if err = p.verifyAndResume(); !errors.Is(err, syscall.Errno(5)) {
			t.Fatalf("assignment was not rejected: %v", err)
		}
		p.job = original
		if _, err = os.Stat(filepath.Join(filepath.Dir(exe), "observation.json")); !os.IsNotExist(err) {
			t.Fatalf("unassigned host executed: %v", err)
		}
		if err = p.abort(); err != nil {
			t.Fatal(err)
		}
		assertExited(t, host)
	})
	t.Run("creation-failure-closes-owned-handles", func(t *testing.T) {
		if c, err := Start(configFor(filepath.Join(t.TempDir(), "missing.exe"))); err == nil || c != nil {
			t.Fatalf("missing executable accepted: %v", err)
		}
	})
	t.Run("ready-activate-health-graceful", func(t *testing.T) {
		exe := fixture(t, "normal")
		c, err := Start(configFor(exe))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Stop()
		if c.State() != Candidate || c.CanCollect() {
			t.Fatal("candidate state lost")
		}
		if err = c.Activate(); err == nil {
			t.Fatal("candidate activated before Ready")
		}
		if err = c.AwaitReady(); err != nil {
			t.Fatal(err)
		}
		if c.State() != Ready || c.CanCollect() {
			t.Fatal("ready host is active or collectable")
		}
		if err = c.Health(); err == nil {
			t.Fatal("ready host health accepted before activation")
		}
		o := readObservation(t, exe)
		p := c.process.(*windowsProcess)
		for _, h := range []uintptr{uintptr(p.job), uintptr(p.pi.Process), uintptr(p.pi.Thread), p.read.Fd(), p.write.Fd()} {
			var flags uint32
			r, _, err := kernel.NewProc("GetHandleInformation").Call(h, uintptr(unsafe.Pointer(&flags)))
			if r == 0 || flags&syscall.HANDLE_FLAG_INHERIT != 0 {
				t.Fatalf("owner handle can inherit: flags=%d error=%v", flags, err)
			}
		}
		host, leaf := retain(t, o.HostPID, p.job), retain(t, o.LeafPID, p.job)
		if err = c.Activate(); err != nil {
			t.Fatal(err)
		}
		if c.State() != Active {
			t.Fatal("activation state lost")
		}
		if err = c.Health(); err != nil {
			t.Fatal(err)
		}
		if c.State() != Healthy {
			t.Fatal("health state lost")
		}
		result, err := c.Stop()
		if err != nil || result.Forced || !c.CanCollect() {
			t.Fatalf("graceful stop: %+v %v", result, err)
		}
		assertExited(t, host)
		assertExited(t, leaf)
	})
	for _, mode := range []string{"no-ready", "malformed", "oversized", "wrong-instance"} {
		t.Run(mode, func(t *testing.T) {
			exe := fixture(t, mode)
			config := configFor(exe)
			config.ReadinessTimeout = 500 * time.Millisecond
			c, err := Start(config)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Stop()
			p := c.process.(*windowsProcess)
			host := retain(t, p.pi.ProcessId, p.job)
			if err = c.AwaitReady(); err == nil {
				t.Fatal("invalid readiness accepted")
			}
			if !c.CanCollect() {
				t.Fatalf("failed candidate not contained: %v", err)
			}
			assertExited(t, host)
			readObservation(t, exe)
		})
	}
	for _, mode := range []string{"stop-hang", "orphan-on-stop", "health-hang", "stale-health"} {
		t.Run(mode, func(t *testing.T) {
			exe := fixture(t, mode)
			c, err := Start(configFor(exe))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Stop()
			if err = c.AwaitReady(); err != nil {
				t.Fatal(err)
			}
			o := readObservation(t, exe)
			p := c.process.(*windowsProcess)
			host, leaf := retain(t, o.HostPID, p.job), retain(t, o.LeafPID, p.job)
			if mode == "health-hang" || mode == "stale-health" {
				if err = c.Activate(); err != nil {
					t.Fatal(err)
				}
				if err = c.Health(); err == nil {
					t.Fatal("hung health accepted")
				}
			} else {
				result, err := c.Stop()
				if err != nil || !result.Forced {
					t.Fatalf("forced stop %+v %v", result, err)
				}
			}
			if !c.CanCollect() {
				t.Fatal("forced teardown not proved")
			}
			assertExited(t, host)
			assertExited(t, leaf)
		})
	}
	t.Run("owner-death", func(t *testing.T) {
		exe := fixture(t, "owner-death")
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerProcess$")
		cmd.Env = append(os.Environ(), "ONECONTROL_HOST_OWNER_HELPER=1", "ONECONTROL_HOST_FIXTURE="+exe, "ONECONTROL_HOST_OBSERVER="+strconv.Itoa(os.Getpid()))
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		ready := make(chan string, 1)
		go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
		var query syscall.Handle
		select {
		case line := <-ready:
			h, err := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
			if err != nil || h == 0 {
				t.Fatalf("owner: %q", line)
			}
			query = syscall.Handle(h)
		case <-time.After(10 * time.Second):
			t.Fatal("owner timeout")
		}
		defer func() {
			if query != 0 {
				syscall.CloseHandle(query)
			}
		}()
		o := readObservation(t, exe)
		var list struct {
			Assigned, Count uint32
			PIDs            [64]uintptr
		}
		r, _, err := queryJob.Call(uintptr(query), 3, uintptr(unsafe.Pointer(&list)), unsafe.Sizeof(list), 0)
		if err = checked(r, err, "QueryInformationJobObject(owner death members)"); err != nil {
			t.Fatal(err)
		}
		if list.Count > 64 || list.Count != list.Assigned {
			t.Fatal("incomplete owned process list")
		}
		handles := []syscall.Handle{}
		seenHost, seenLeaf := false, false
		for _, pid := range list.PIDs[:list.Count] {
			handles = append(handles, retain(t, uint32(pid), query))
			seenHost = seenHost || uint32(pid) == o.HostPID
			seenLeaf = seenLeaf || uint32(pid) == o.LeafPID
		}
		if err = syscall.CloseHandle(query); err != nil {
			t.Fatal(err)
		}
		query = 0
		if !seenHost || !seenLeaf {
			t.Fatal("job list omitted the known fixture processes")
		}
		t.Logf("retained %d exact job members, closed query handle before killing owner", len(handles))
		if err = cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err = cmd.Wait(); err == nil {
			t.Fatal("killed owner succeeded")
		}
		for _, h := range handles {
			assertExited(t, h)
		}
	})
	t.Run("unknown-containment-blocks-collection", func(t *testing.T) {
		exe := fixture(t, "normal")
		c, err := Start(configFor(exe))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Stop()
		if err = c.AwaitReady(); err != nil {
			t.Fatal(err)
		}
		p := c.process.(*windowsProcess)
		original := p.job
		current, err := syscall.GetCurrentProcess()
		if err != nil {
			t.Fatal(err)
		}
		var limited syscall.Handle
		if err = syscall.DuplicateHandle(current, original, current, &limited, 8, false, 0); err != nil {
			t.Fatal(err)
		}
		p.job = limited
		defer func() { syscall.CloseHandle(limited); p.job = original; p.terminate(); c.waitEmpty(); p.close() }()
		if _, err = c.Stop(); !errors.Is(err, ErrContainment) {
			t.Fatalf("unproved stop accepted: %v", err)
		}
		if c.State() != ContainmentUnknown || c.CanCollect() {
			t.Fatal("unknown containment permitted collection")
		}
		if _, err = c.Stop(); !errors.Is(err, ErrContainment) {
			t.Fatal("unknown containment silently retried")
		}
	})
}
