package authority

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"onecontrol/native/internal/contracts"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func checkpointFixture() contracts.Checkpoint {
	return contracts.Checkpoint{RootVersion: "1", AuthorityEpoch: "7", Revision: "12", PolicyDigest: strings.Repeat("a", 64), BindingDigest: strings.Repeat("b", 64), SeenAt: testNow, Nonce: strings.Repeat("A", 43)}
}

func TestCheckpointOwnerProcess(t *testing.T) {
	if os.Getenv("ONECONTROL_CHECKPOINT_OWNER") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := OpenStore(ctx, os.Getenv("ONECONTROL_CHECKPOINT_PATH"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "checkpoint open:", err)
		os.Exit(3)
	}
	if err = s.Commit(nil, checkpointFixture()); err != nil {
		fmt.Fprintln(os.Stderr, "checkpoint commit:", err)
		os.Exit(4)
	}
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	fmt.Println("committed")
	bufio.NewReader(os.Stdin).ReadByte()
	runtime.KeepAlive(s)
	os.Exit(0)
}

func TestCheckpointCrashReleasePreservesFloor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "authority.journal")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCheckpointOwnerProcess$")
	cmd.Env = append(os.Environ(), "ONECONTROL_CHECKPOINT_OWNER=1", "ONECONTROL_CHECKPOINT_PATH="+path)
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
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "committed\n" {
			cmd.Process.Kill()
			exit := <-exited
			t.Fatalf("owner readiness %q, exit %v, state %v, stderr %q", line, exit, cmd.ProcessState, diagnostics.String())
		}
	case <-ctx.Done():
		cmd.Process.Kill()
		exit := <-exited
		t.Fatalf("owner readiness timeout, exit %v, state %v, stderr %q", exit, cmd.ProcessState, diagnostics.String())
	}
	before, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	contender, stop := context.WithTimeout(ctx, 80*time.Millisecond)
	defer stop()
	if other, err := OpenStore(contender, path); !errors.Is(err, context.DeadlineExceeded) {
		if other != nil {
			other.Close()
		}
		t.Fatal("concurrent writer accepted", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if exit := <-exited; exit == nil {
		t.Fatal("killed owner exited successfully")
	}
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cp, err := s.Load()
	if err != nil || cp == nil || *cp != checkpointFixture() {
		t.Fatalf("lost flushed floor: %v %v", cp, err)
	}
	after, err := os.Stat(path + ".lock")
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("ownership file replaced: %v", err)
	}
	if err = s.Commit(nil, checkpointFixture()); err == nil {
		t.Fatal("stale compare and swap accepted after owner death")
	}
}

func TestCorruptionReleasesOwnershipAndClosedStoreCannotWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "authority.journal")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Commit(nil, checkpointFixture()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Commit(nil, checkpointFixture()); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed store accepted commit", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenStore(ctx, path); err == nil || err.Error() != "invalid_checkpoint" {
		t.Fatal("corrupt checkpoint accepted", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatal("failed open retained ownership", err)
	}
	s.Close()
}

func TestCheckpointLockRetainsFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "authority.journal")
	store, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatalf("persistent kernel lock file removed: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("lock file identity changed")
	}
	again, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
}
