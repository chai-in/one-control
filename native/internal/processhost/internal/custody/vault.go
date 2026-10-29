package custody

import (
	"context"
	"errors"
	"sync"
)

var (
	errCapacity = errors.New("custody capacity exhausted")
	errSealed   = errors.New("writer sealed")
	errBinding  = errors.New("immutable request binding mismatch")
	errState    = errors.New("invalid custody transition")
	errRetained = errors.New("dispatched obligations retained")
)

type budget struct {
	sessions, queued, dispatched, terminals, tombstones, responses, controls int
}

type limits struct {
	writers         int
	service, writer budget
}

func (l limits) validate() error {
	a := []int{l.writer.sessions, l.writer.queued, l.writer.dispatched, l.writer.terminals, l.writer.tombstones, l.writer.responses, l.writer.controls}
	b := []int{l.service.sessions, l.service.queued, l.service.dispatched, l.service.terminals, l.service.tombstones, l.service.responses, l.service.controls}
	if l.writers < 1 || l.writers > 4096 {
		return errCapacity
	}
	for i := range a {
		if a[i] < 1 || b[i] < a[i] || b[i] > 65536 {
			return errCapacity
		}
	}
	if l.writer.dispatched > l.writer.terminals || l.service.dispatched > l.service.terminals || l.writer.queued > l.writer.tombstones || l.service.queued > l.service.tombstones || l.writers*l.writer.controls > l.service.controls {
		return errCapacity
	}
	return nil
}

type registry struct {
	mu      sync.Mutex
	limits  limits
	used    budget
	writers map[string]*vault
}

func newRegistry(l limits) (*registry, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &registry{limits: l, writers: make(map[string]*vault)}, nil
}

func (r *registry) register(key string, v *vault) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(key) == 0 || len(key) > 128 || v == nil || v.registry != r {
		return errState
	}
	if r.writers[key] != nil {
		return errBinding
	}
	if len(r.writers) >= r.limits.writers || r.used.controls+r.limits.writer.controls > r.limits.service.controls {
		return errCapacity
	}
	r.writers[key] = v
	r.used.controls += r.limits.writer.controls
	return nil
}

func (r *registry) reserve(own *budget, delta budget) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, b := add(*own, delta), add(r.used, delta)
	if !within(a, r.limits.writer) || !within(b, r.limits.service) {
		return false
	}
	*own, r.used = a, b
	return true
}

func add(a, b budget) budget {
	return budget{a.sessions + b.sessions, a.queued + b.queued, a.dispatched + b.dispatched, a.terminals + b.terminals, a.tombstones + b.tombstones, a.responses + b.responses, a.controls + b.controls}
}

func within(a, b budget) bool {
	return a.sessions >= 0 && a.sessions <= b.sessions && a.queued >= 0 && a.queued <= b.queued && a.dispatched >= 0 && a.dispatched <= b.dispatched && a.terminals >= 0 && a.terminals <= b.terminals && a.tombstones >= 0 && a.tombstones <= b.tombstones && a.responses >= 0 && a.responses <= b.responses && a.controls >= 0 && a.controls <= b.controls
}

type phase uint8

const (
	queued phase = iota + 1
	dispatched
	returned
	canceled
	retired
)

type request struct {
	id      string
	binding [32]byte
	resume  bool
}

type attempt struct {
	request request
	phase   phase
	cancel  context.CancelFunc
	result  workResult
}

type workResult uint8

const (
	workReturned workResult = iota + 1
	workCanceled
)

type worker interface {
	run(context.Context) workResult
}
type terminal struct {
	id     string
	result workResult
}

type operation uint8

const (
	attach operation = iota + 1
	detach
	admit
	dispatch
	inspect
	retire
	shutdown
)

type command struct {
	op      operation
	session uint64
	request request
	work    worker
	reply   chan result
}

type view struct {
	sealed                                                            bool
	cause                                                             sealCause
	sessions, queued, outstanding, returned, canceled, retired, joins int
	states                                                            map[string]phase
	requests                                                          map[string]request
}

type result struct {
	session uint64
	phase   phase
	view    view
	err     error
}

type vault struct {
	registry       *registry
	peer           writerPeer
	ordinary       chan command
	control        chan command
	terminals      chan terminal
	sealRequest    chan struct{}
	watchDone      chan struct{}
	watchErr       error
	stopWatch      chan struct{}
	done           chan struct{}
	sealedEvent    chan struct{}
	drained        chan struct{}
	closeOnce      sync.Once
	workers        sync.WaitGroup
	responseMu     sync.Mutex
	submitMu       sync.Mutex
	activeControls int
	responseUsed   budget
	used           budget
	sealed         bool
	cause          sealCause
	drainedClosed  bool
	nextSession    uint64
	sessions       map[uint64]bool
	attempts       map[string]*attempt
	joins          int
}

type writerPeer interface {
	dead() (bool, error)
	watch(stop <-chan struct{}) error
}

type sealCause uint8

const (
	writerExited sealCause = iota + 1
	observationFailed
	closeRequested
)

type drainResult struct {
	ledgerDrained bool
	err           error
}

func (v *vault) observedSeal() {
	cause := writerExited
	if v.watchErr != nil {
		cause = observationFailed
	}
	v.reduceSeal(cause)
}

func (v *vault) run() {
	sealEvents, deaths := v.sealRequest, v.watchDone
	for {
		var c command
		select {
		case <-sealEvents:
			v.reduceSeal(closeRequested)
			sealEvents = nil
		default:
		}
		select {
		case <-deaths:
			v.observedSeal()
			deaths = nil
		default:
		}
		select {
		case t := <-v.terminals:
			v.reduceTerminal(t)
			continue
		default:
		}
		select {
		case <-sealEvents:
			v.reduceSeal(closeRequested)
			sealEvents = nil
			continue
		case <-deaths:
			v.observedSeal()
			deaths = nil
			continue
		case t := <-v.terminals:
			v.reduceTerminal(t)
			continue
		case c = <-v.control:
		case c = <-v.ordinary:
		}
		// The observation and following memory decision share this runner. The reducer does no kernel I/O.
		dead, err := v.peer.dead()
		if dead || err != nil {
			cause := writerExited
			if err != nil {
				cause = observationFailed
			}
			v.reduceSeal(cause)
		}
		if c.op == shutdown {
			v.submitMu.Lock()
		}
		out := v.reduce(c)
		v.releaseResponse(isControl(c.op))
		if c.op == shutdown {
			if out.err == nil {
				close(v.done)
			}
			v.submitMu.Unlock()
		}
		c.reply <- out
		if c.op == shutdown && out.err == nil {
			return
		}
	}
}

func (v *vault) reduceSeal(cause sealCause) {
	if v.sealed {
		return
	}
	v.sealed = true
	v.cause = cause
	close(v.sealedEvent)
	for _, a := range v.attempts {
		switch a.phase {
		case queued:
			a.phase = canceled
			v.registry.reserve(&v.used, budget{queued: -1})
		case dispatched:
			a.cancel()
		}
	}
	v.checkDrained()
}

func (v *vault) checkDrained() {
	if v.sealed && v.used.dispatched == 0 && !v.drainedClosed {
		v.drainedClosed = true
		close(v.drained)
	}
}

func (v *vault) reduceTerminal(t terminal) {
	a := v.attempts[t.id]
	if a == nil || a.phase != dispatched {
		panic("unreserved terminal completion")
	}
	a.cancel()
	a.phase, a.result = returned, t.result
	v.joins++
	v.registry.reserve(&v.used, budget{dispatched: -1})
	v.checkDrained()
}

func (v *vault) snapshot() view {
	s := view{sealed: v.sealed, sessions: len(v.sessions), queued: v.used.queued, outstanding: v.used.dispatched, joins: v.joins, states: make(map[string]phase, len(v.attempts)), requests: make(map[string]request, len(v.attempts))}
	s.cause = v.cause
	for id, a := range v.attempts {
		s.states[id] = a.phase
		s.requests[id] = a.request
		switch a.phase {
		case returned:
			s.returned++
		case canceled:
			s.canceled++
		case retired:
			s.retired++
		}
	}
	return s
}

func (v *vault) reduce(c command) result {
	switch c.op {
	case attach:
		if v.nextSession == ^uint64(0) {
			return result{err: errCapacity}
		}
		if !v.registry.reserve(&v.used, budget{sessions: 1}) {
			return result{err: errCapacity}
		}
		v.nextSession++
		v.sessions[v.nextSession] = true
		return result{session: v.nextSession}
	case detach:
		if !v.sessions[c.session] {
			return result{err: errState}
		}
		delete(v.sessions, c.session)
		v.registry.reserve(&v.used, budget{sessions: -1})
	case admit:
		if v.sealed {
			return result{err: errSealed}
		}
		if !v.sessions[c.session] || len(c.request.id) == 0 || len(c.request.id) > 128 {
			return result{err: errState}
		}
		if a := v.attempts[c.request.id]; a != nil {
			if a.request != c.request {
				return result{err: errBinding}
			}
			return result{phase: a.phase}
		}
		if !v.registry.reserve(&v.used, budget{queued: 1, terminals: 1, tombstones: 1}) {
			return result{err: errCapacity}
		}
		v.attempts[c.request.id] = &attempt{request: c.request, phase: queued}
		return result{phase: queued}
	case dispatch:
		if v.sealed {
			return result{err: errSealed}
		}
		a := v.attempts[c.request.id]
		if a == nil || a.phase != queued || c.work == nil {
			return result{err: errState}
		}
		if a.request != c.request {
			return result{err: errBinding}
		}
		if !v.registry.reserve(&v.used, budget{queued: -1, dispatched: 1}) {
			return result{err: errCapacity}
		}
		a.phase = dispatched
		ctx, cancel := context.WithCancel(context.Background())
		a.cancel = cancel
		v.startWorker(c.request.id, ctx, c.work)
		return result{phase: dispatched}
	case inspect:
		return result{view: v.snapshot()}
	case retire:
		a := v.attempts[c.request.id]
		if a == nil || a.request != c.request {
			return result{err: errBinding}
		}
		if a.phase == retired {
			return result{phase: retired}
		}
		if a.phase != returned && a.phase != canceled {
			return result{err: errRetained}
		}
		a.phase = retired
		v.registry.reserve(&v.used, budget{terminals: -1})
		return result{phase: retired}
	case shutdown:
		if !v.sealed || v.used.dispatched != 0 || len(v.sessions) != 0 || v.used.terminals != 0 || len(v.ordinary) != 0 || len(v.control) != 0 {
			return result{err: errRetained}
		}
	default:
		return result{err: errState}
	}
	return result{}
}

func (v *vault) startWorker(id string, ctx context.Context, w worker) {
	var finished sync.WaitGroup
	finished.Add(1)
	var outcome workResult
	v.workers.Add(2)
	go func() {
		defer finished.Done()
		defer v.workers.Done()
		outcome = w.run(ctx)
	}()
	go func() {
		defer v.workers.Done()
		finished.Wait()
		v.terminals <- terminal{id: id, result: outcome}
	}()
}

func (v *vault) call(ctx context.Context, c command) result {
	v.submitMu.Lock()
	select {
	case <-v.done:
		v.submitMu.Unlock()
		return result{err: errState}
	default:
	}
	if err := ctx.Err(); err != nil {
		v.submitMu.Unlock()
		return result{err: err}
	}
	control := isControl(c.op)
	v.responseMu.Lock()
	reserved := false
	if control {
		if v.activeControls < v.registry.limits.writer.controls {
			v.activeControls++
			reserved = true
		}
	} else {
		reserved = v.registry.reserve(&v.responseUsed, budget{responses: 1})
	}
	v.responseMu.Unlock()
	if !reserved {
		v.submitMu.Unlock()
		return result{err: errCapacity}
	}
	c.reply = make(chan result, 1)
	ch := v.ordinary
	if control {
		ch = v.control
	}
	select {
	case ch <- c:
	default:
		v.releaseResponse(control)
		v.submitMu.Unlock()
		return result{err: errCapacity}
	}
	v.submitMu.Unlock()
	select {
	case out := <-c.reply:
		return out
	case <-ctx.Done():
		return result{err: ctx.Err()}
	}
}

func isControl(op operation) bool {
	return op == inspect || op == detach || op == retire || op == shutdown
}

func (v *vault) releaseResponse(control bool) {
	v.responseMu.Lock()
	defer v.responseMu.Unlock()
	if control {
		v.activeControls--
		return
	}
	if !v.registry.reserve(&v.responseUsed, budget{responses: -1}) {
		panic("response reservation lost")
	}
}

func (v *vault) close(ctx context.Context) drainResult {
	v.closeOnce.Do(func() { close(v.sealRequest) })
	select {
	case <-v.drained:
		return drainResult{ledgerDrained: true}
	case <-ctx.Done():
		return drainResult{err: errRetained}
	}
}
