package custody

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var peerExecutable string
var custodyKernel = syscall.NewLazyDLL("kernel32.dll")
var custodyCompare = syscall.NewLazyDLL("kernelbase.dll").NewProc("CompareObjectHandles")

func sameWriter(a, b *writerProcess) bool {
	r, _, _ := custodyCompare.Call(uintptr(a.handle), uintptr(b.handle))
	return r != 0
}

func TestMain(m *testing.M) {
	if e := custodyCompare.Find(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	output := os.Getenv("CUSTODY_TEST_OUTPUT")
	if output == "" {
		output = filepath.Join("..", "..", "..", "..", "..", ".local", "alpha-work", "custody")
	}
	if e := os.MkdirAll(output, 0700); e != nil {
		panic(e)
	}
	var e error
	peerExecutable, e = filepath.Abs(filepath.Join(output, "peer.exe"))
	if e != nil {
		panic(e)
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	c := exec.Command(goTool, "build", "-trimpath", "-o", peerExecutable, "./testdata/peer")
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if b, e := c.CombinedOutput(); e != nil {
		fmt.Fprintf(os.Stderr, "fixture build: %v %s\n", e, b)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func testLimits() limits {
	return limits{writers: 4, service: budget{sessions: 16, queued: 32, dispatched: 8, terminals: 32, tombstones: 64, responses: 16, controls: 8}, writer: budget{sessions: 4, queued: 8, dispatched: 2, terminals: 8, tombstones: 16, responses: 4, controls: 2}}
}

// Only this test file can construct a vault from a same-user process. No production authentication capability exists.
func pinTestWriter(t *testing.T, r *registry, key string, p *writerProcess, delay ...<-chan struct{}) *vault {
	t.Helper()
	if dead, e := p.dead(); e != nil || dead {
		t.Fatalf("pin live writer: %v %v", dead, e)
	}
	for k, v := range r.writers {
		if sameWriter(v.peer.(*writerProcess), p) {
			if k != key {
				t.Fatal("same exact writer under a second key")
			}
			return v
		}
	}
	if len(r.writers) >= r.limits.writers {
		t.Fatal("writer fence capacity")
	}
	v := &vault{registry: r, peer: p, ordinary: make(chan command, r.limits.writer.responses), control: make(chan command, r.limits.writer.controls), terminals: make(chan terminal, r.limits.writer.dispatched), sealRequest: make(chan struct{}), watchDone: make(chan struct{}), stopWatch: make(chan struct{}), done: make(chan struct{}), sealedEvent: make(chan struct{}), drained: make(chan struct{}), sessions: make(map[uint64]bool), attempts: make(map[string]*attempt)}
	want(t, r.register(key, v), nil)
	go func() { v.watchErr = p.watch(v.stopWatch); close(v.watchDone) }()
	go func() {
		if len(delay) > 0 {
			<-delay[0]
		}
		v.run()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := v.close(ctx).err; e != nil {
			t.Errorf("cleanup retained worker: %v", e)
			return
		}
		s := v.call(ctx, command{op: inspect}).view
		for id := range s.states {
			if e := v.call(ctx, command{op: retire, request: s.requests[id]}).err; e != nil {
				t.Errorf("retire %s: %v", id, e)
			}
		}
		if s.sessions != 0 {
			t.Errorf("session workers were not joined and detached: %d", s.sessions)
			return
		}
		if e := v.call(ctx, command{op: shutdown}).err; e != nil {
			t.Errorf("shutdown: %v", e)
			return
		}
		await(t, v.done, "vault owner join")
		close(v.stopWatch)
		await(t, v.watchDone, "exact-handle watcher join")
		v.workers.Wait()
		t.Logf("joined owner=1 watcher=1 dispatched=%d; ledger drain is not host proof", v.joins)
	})
	return v
}

func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		t.Fatalf("deadline waiting for %s", what)
	}
}

func closeFile(t *testing.T, p *os.File) {
	t.Helper()
	if e := p.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
		t.Errorf("owned file cleanup: %v", e)
	}
}

func call(t *testing.T, v *vault, c command) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return v.call(ctx, c)
}

func want(t *testing.T, got, wanted error) {
	t.Helper()
	if !errors.Is(got, wanted) {
		t.Fatalf("got %v, want %v", got, wanted)
	}
}

func req(id string) request {
	return request{id: id, binding: sha256.Sum256([]byte("fixed-binding-" + id))}
}

type pipeEnds struct{ read, write *os.File }
type fixture struct {
	process  *writerProcess
	control  *os.File
	ackRead  *os.File
	acks     chan string
	ackDone  chan struct{}
	ends     [2]pipeEnds
	killOnce sync.Once
}

func makePipe(t *testing.T, childRead bool) (*os.File, *os.File) {
	t.Helper()
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	var r, w syscall.Handle
	if e := syscall.CreatePipe(&r, &w, &sa, 4096); e != nil {
		t.Fatal(e)
	}
	parent := r
	if childRead {
		parent = w
	}
	if e := syscall.SetHandleInformation(parent, syscall.HANDLE_FLAG_INHERIT, 0); e != nil {
		t.Fatal(e)
	}
	return os.NewFile(uintptr(r), "fixture-pipe-read"), os.NewFile(uintptr(w), "fixture-pipe-write")
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{acks: make(chan string, 8), ackDone: make(chan struct{})}
	var child []*os.File
	cr, cw := makePipe(t, true)
	f.control = cw
	child = append(child, cr)
	ar, aw := makePipe(t, false)
	f.ackRead = ar
	child = append(child, aw)
	args := syscall.EscapeArg(peerExecutable)
	for i := 0; i < 2; i++ {
		rw, ww := makePipe(t, false)
		rr, wr := makePipe(t, true)
		f.ends[i] = pipeEnds{read: rw, write: wr}
		child = append(child, rr, ww)
		args += fmt.Sprintf(" %d %d", rr.Fd(), ww.Fd())
	}
	handles := make([]syscall.Handle, len(child))
	for i, p := range child {
		handles[i] = syscall.Handle(p.Fd())
	}
	initAttrs := custodyKernel.NewProc("InitializeProcThreadAttributeList")
	updateAttrs := custodyKernel.NewProc("UpdateProcThreadAttribute")
	deleteAttrs := custodyKernel.NewProc("DeleteProcThreadAttributeList")
	var size uintptr
	initAttrs.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	storage := make([]byte, size)
	attrs := unsafe.Pointer(&storage[0])
	if ok, _, e := initAttrs.Call(uintptr(attrs), 1, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		t.Fatal(e)
	}
	defer deleteAttrs.Call(uintptr(attrs))
	if ok, _, e := updateAttrs.Call(uintptr(attrs), 0, 0x20002, uintptr(unsafe.Pointer(&handles[0])), uintptr(len(handles))*unsafe.Sizeof(handles[0]), 0, 0); ok == 0 {
		t.Fatal(e)
	}
	type startup struct {
		syscall.StartupInfo
		attrs unsafe.Pointer
	}
	si := startup{attrs: attrs}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES
	si.StdInput = syscall.Handle(cr.Fd())
	si.StdOutput = syscall.Handle(aw.Fd())
	si.StdErr = si.StdOutput
	app, _ := syscall.UTF16PtrFromString(peerExecutable)
	line, _ := syscall.UTF16PtrFromString(args)
	var pi syscall.ProcessInformation
	e := syscall.CreateProcess(app, line, nil, nil, true, 0x80000|0x8000000, nil, nil, &si.StartupInfo, &pi)
	runtime.KeepAlive(storage)
	runtime.KeepAlive(handles)
	for _, p := range child {
		if ce := p.Close(); ce != nil {
			t.Error(ce)
		}
	}
	if e != nil {
		t.Fatal(e)
	}
	if e := syscall.CloseHandle(pi.Thread); e != nil {
		t.Fatal(e)
	}
	f.process = &writerProcess{handle: pi.Process}
	go func() {
		defer close(f.ackDone)
		s := bufio.NewScanner(ar)
		for s.Scan() {
			f.acks <- s.Text()
		}
	}()
	t.Cleanup(func() {
		f.kill(t)
		await(t, f.ackDone, "fixture stdout reader join")
		for _, p := range []*os.File{f.control, f.ackRead, f.ends[0].read, f.ends[0].write, f.ends[1].read, f.ends[1].write} {
			closeFile(t, p)
		}
		if e := syscall.CloseHandle(f.process.handle); e != nil {
			t.Error(e)
		}
		t.Log("fixture process=1 original process handle closed after watcher join; primary thread closed; stdout reader joined=1")
	})
	return f
}

func (f *fixture) kill(t *testing.T) {
	t.Helper()
	f.killOnce.Do(func() {
		dead, e := f.process.dead()
		if e != nil {
			t.Error(e)
			return
		}
		if !dead {
			if e := syscall.TerminateProcess(f.process.handle, 91); e != nil {
				t.Error(e)
				return
			}
		}
		n, e := syscall.WaitForSingleObject(f.process.handle, 3000)
		if e != nil || n != syscall.WAIT_OBJECT_0 {
			t.Errorf("exact fixture termination: %d %v", n, e)
		}
	})
}

func (f *fixture) issue(t *testing.T, session int, frame string, read bool) string {
	t.Helper()
	b, e := json.Marshal(struct {
		Session int
		Frame   string
		Read    bool
	}{session, frame, read})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := fmt.Fprintln(f.control, string(b)); e != nil {
		t.Fatal(e)
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case a := <-f.acks:
		return a
	case <-timer.C:
		t.Fatal("fixture instruction deadline")
		return ""
	}
}

type gate struct {
	entered, release chan struct{}
	once             sync.Once
}

func newGate() *gate  { return &gate{entered: make(chan struct{}), release: make(chan struct{})} }
func (g *gate) open() { g.once.Do(func() { close(g.release) }) }

type observed struct {
	request request
	err     error
}
type session struct {
	id            uint64
	observations  chan observed
	done          chan struct{}
	detachOnce    sync.Once
	writeStarted  chan struct{}
	writeReturned chan struct{}
}

func (s *session) detach(t *testing.T, v *vault) {
	s.detachOnce.Do(func() { want(t, call(t, v, command{op: detach, session: s.id}).err, nil) })
}

func startSession(t *testing.T, f *fixture, v *vault, ends pipeEnds, beforeRead, afterParse *gate, stall bool) *session {
	t.Helper()
	a := call(t, v, command{op: attach})
	want(t, a.err, nil)
	s := &session{id: a.session, observations: make(chan observed, 16), done: make(chan struct{}), writeStarted: make(chan struct{}), writeReturned: make(chan struct{})}
	replies := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(replies)
		scanner := bufio.NewScanner(ends.read)
		scanner.Buffer(make([]byte, 512), 512)
		for scanner.Scan() {
			id := scanner.Text()
			r := req(id)
			if strings.HasPrefix(id, "resume-") {
				r.resume = true
			}
			if afterParse != nil && id == "late-parsed" {
				close(afterParse.entered)
				<-afterParse.release
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			out := v.call(ctx, command{op: admit, session: s.id, request: r})
			cancel()
			s.observations <- observed{request: r, err: out.err}
			reply := "admitted"
			if out.err != nil {
				reply = out.err.Error()
			}
			replies <- reply
			if beforeRead != nil && id == "useful-two" {
				close(beforeRead.entered)
				<-beforeRead.release
			}
		}
	}()
	go func() {
		defer wg.Done()
		for reply := range replies {
			big := stall
			if big {
				reply = strings.Repeat("x", 128*1024)
				stall = false
				close(s.writeStarted)
			}
			_, e := fmt.Fprintln(ends.write, reply)
			if big {
				close(s.writeReturned)
			}
			if e != nil {
				return
			}
		}
	}()
	go func() { wg.Wait(); close(s.done) }()
	t.Cleanup(func() {
		f.kill(t)
		if beforeRead != nil {
			beforeRead.open()
		}
		if afterParse != nil {
			afterParse.open()
		}
		await(t, s.done, "actual pipe reader and writer joins")
		s.detach(t, v)
		closeFile(t, ends.read)
		closeFile(t, ends.write)
		t.Log("transport session=1 pipe reader joined=1 pipe writer joined=1 join coordinator=1; reply I/O is distinct from owner admission")
	})
	return s
}

func observe(t *testing.T, s *session, wanted error) request {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case o := <-s.observations:
		want(t, o.err, wanted)
		return o.request
	case <-timer.C:
		t.Fatal("owner admission observation deadline")
		return request{}
	}
}

type testWorker struct {
	entered, release chan struct{}
	effects          *atomic.Int32
}

func (w testWorker) run(ctx context.Context) workResult {
	if w.entered != nil {
		close(w.entered)
	}
	if w.release != nil {
		<-w.release
	}
	if w.effects != nil {
		w.effects.Add(1)
	}
	if ctx.Err() != nil {
		return workCanceled
	}
	return workReturned
}

func joined(t *testing.T, v *vault, n int) view {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s := call(t, v, command{op: inspect}).view
		if s.joins == n {
			return s
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("joins got %d want %d", s.joins, n)
		}
	}
}

func TestAutomaticDeathSealsParsedUnreadAndReconnect(t *testing.T) {
	r, e := newRegistry(testLimits())
	want(t, e, nil)
	f := startFixture(t)
	v := pinTestWriter(t, r, "writer-one", f.process)
	parsed, unread := newGate(), newGate()
	s1 := startSession(t, f, v, f.ends[0], nil, parsed, false)
	s2 := startSession(t, f, v, f.ends[1], unread, nil, false)
	f.issue(t, 0, "useful", false)
	q := observe(t, s1, nil)
	if a := f.issue(t, 0, "", true); a != "admitted" {
		t.Fatal(a)
	}
	want(t, call(t, v, command{op: admit, session: s1.id, request: q}).err, nil)
	changed := q
	changed.binding[0] ^= 1
	want(t, call(t, v, command{op: admit, session: s1.id, request: changed}).err, errBinding)
	var effects atomic.Int32
	want(t, call(t, v, command{op: dispatch, request: q, work: testWorker{effects: &effects}}).err, nil)
	if s := joined(t, v, 1); s.outstanding != 0 || effects.Load() != 1 {
		t.Fatal(s, effects.Load())
	}
	f.issue(t, 1, "useful-two", false)
	observe(t, s2, nil)
	f.issue(t, 1, "", true)
	f.issue(t, 0, "late-parsed", false)
	await(t, parsed.entered, "parsed old command")
	await(t, unread.entered, "reader held before next frame")
	f.issue(t, 1, "resume-unread", false)
	f.kill(t)
	await(t, v.sealedEvent, "automatic exact-process watcher seal")
	if s := call(t, v, command{op: inspect}).view; s.cause != writerExited {
		t.Fatal("seal was not exact writer death", s.cause)
	}
	parsed.open()
	unread.open()
	observe(t, s1, errSealed)
	observe(t, s2, errSealed)
	await(t, s1.done, "parsed session join")
	await(t, s2.done, "unread session join")
	s1.detach(t, v)
	s2.detach(t, v)
	// A new transport attaches to the old vault. The peer binding here is test construction, not authentication.
	rr2, ww2, e := os.Pipe()
	want(t, e, nil)
	rx, wx, e := os.Pipe()
	want(t, e, nil)
	s5 := startSession(t, f, v, pipeEnds{rr2, wx}, nil, nil, false)
	fmt.Fprintln(ww2, "reconnected-old")
	observe(t, s5, errSealed)
	closeFile(t, ww2)
	closeFile(t, rx)
	await(t, s5.done, "new stale transport join")
	t.Log("actual writer death=1; fixture-origin sessions=2; test stale reconnect transports=1; no explicit seal before watcher assertion")
}

func TestDispatchedObligationSurvivesDeadlineAndQueueCancels(t *testing.T) {
	r, e := newRegistry(testLimits())
	want(t, e, nil)
	f := startFixture(t)
	v := pinTestWriter(t, r, "held-writer", f.process)
	s := startSession(t, f, v, f.ends[0], nil, nil, true)
	f.issue(t, 0, "held", false)
	held := observe(t, s, nil)
	await(t, s.writeStarted, "ordinary response write started")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	want(t, call(t, v, command{op: dispatch, request: held, work: testWorker{entered: entered, release: release}}).err, nil)
	await(t, entered, "actual dispatched worker entered")
	f.issue(t, 1, "queued", false)
	s2 := startSession(t, f, v, f.ends[1], nil, nil, false)
	q := observe(t, s2, nil)
	select {
	case <-s.writeReturned:
		t.Fatal("unread oversized response unexpectedly returned")
	default:
	}
	f.kill(t)
	await(t, v.sealedEvent, "automatic seal despite stalled response writer")
	await(t, s.writeReturned, "actual blocked pipe write returned after test peer death")
	state := call(t, v, command{op: inspect}).view
	if state.states[q.id] != canceled || state.outstanding != 1 || state.joins != 0 {
		t.Fatal(state)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	want(t, v.close(ctx).err, errRetained)
	var callers sync.WaitGroup
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			c, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			want(t, v.close(c).err, errRetained)
		}()
	}
	callers.Wait()
	want(t, call(t, v, command{op: retire, request: held}).err, errRetained)
	if state = call(t, v, command{op: inspect}).view; state.outstanding != 1 {
		t.Fatal(state)
	}
	once.Do(func() { close(release) })
	if state = joined(t, v, 1); state.outstanding != 0 || !state.sealed {
		t.Fatal(state)
	}
	want(t, call(t, v, command{op: dispatch, request: q, work: testWorker{}}).err, errSealed)
	want(t, call(t, v, command{op: admit, session: s.id, request: req("late")}).err, errSealed)
	t.Log("death=1 dispatched-before-seal=1 queued-known-canceled=1 held-worker actual-return-and-join=1; duplicate close callers joined=8; barrier is user space, not CreateProcess")
}

func TestEmptyCloseReportsLedgerDrainOnly(t *testing.T) {
	r, e := newRegistry(testLimits())
	want(t, e, nil)
	f := startFixture(t)
	v := pinTestWriter(t, r, "empty", f.process)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d := v.close(ctx)
	want(t, d.err, nil)
	if !d.ledgerDrained {
		t.Fatal("empty ledger did not drain")
	}
	s := call(t, v, command{op: inspect}).view
	if s.joins != 0 || s.cause != closeRequested {
		t.Fatal(s)
	}
	if dead, e := f.process.dead(); e != nil || dead {
		t.Fatal("ledger close pretended to stop the writer", dead, e)
	}
	t.Log("ledger drained with zero dispatched workers; process, watcher, owner, pipes and handles still require separate actual cleanup")
}
