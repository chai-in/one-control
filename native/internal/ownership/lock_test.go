package ownership

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func acquireTest(path string, wait time.Duration) (*Owner, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return Acquire(ctx, path)
}

func TestOwnershipProcess(t *testing.T) {
	if os.Getenv("ONECONTROL_LOCK_HELPER") != "1" {
		return
	}
	o, err := acquireTest(os.Getenv("ONECONTROL_LOCK_PATH"), 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ownership open:", err)
		os.Exit(3)
	}
	defer o.Close()
	fmt.Fprintln(os.Stdout, "owned")
	bufio.NewReader(os.Stdin).ReadByte()
	runtime.KeepAlive(o)
	os.Exit(0)
}

func TestCompetingProcessAndOwnerDeath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnershipProcess$")
	cmd.Env = append(os.Environ(), "ONECONTROL_LOCK_HELPER=1", "ONECONTROL_LOCK_PATH="+path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); close(exited) }()
	defer func() { cmd.Process.Kill(); in.Close(); <-exited }()
	line := make(chan string, 1)
	go func() { text, _ := bufio.NewReader(out).ReadString('\n'); line <- text }()
	select {
	case text := <-line:
		if text != "owned\n" {
			cmd.Process.Kill()
			exit := <-exited
			t.Fatalf("helper readiness %q, exit %v, state %v, stderr %q", text, exit, cmd.ProcessState, diagnostics.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		exit := <-exited
		t.Fatalf("owner readiness timeout, exit %v, state %v, stderr %q", exit, cmd.ProcessState, diagnostics.String())
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireTest(path, 80*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("concurrent writer accepted: %v", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = <-exited; err == nil {
		t.Fatal("killed owner exited successfully")
	}
	next, err := acquireTest(path, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("persistent file replaced: %v", err)
	}
	if other, err := acquireTest(path, 80*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("ownership released before Close: %v", err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	last, err := acquireTest(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	last.Close()
	if _, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestAcquisitionRequiresBound(t *testing.T) {
	if _, err := Acquire(context.Background(), filepath.Join(t.TempDir(), "lock")); err == nil {
		t.Fatal("unbounded acquisition accepted")
	}
}
