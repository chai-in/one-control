package processhost

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"
)

var ErrUnsupported = errors.New("native child containment is unsupported on this platform")
var ErrContainment = errors.New("child containment could not be proved")

type State uint8

const (
	Candidate State = iota
	Ready
	Active
	Healthy
	Stopped
	ContainmentUnknown
)

type Config struct {
	Executable       string
	Instance         string
	ReadinessTimeout time.Duration
	OperationTimeout time.Duration
	StopTimeout      time.Duration
}

type process interface {
	input() io.Writer
	output() io.Reader
	terminate() error
	empty() (bool, error)
	close() error
}

type Child struct {
	mu       sync.Mutex
	config   Config
	state    State
	process  process
	sequence uint64
}

type StopResult struct{ Forced bool }

func Start(config Config) (*Child, error) {
	nonce, err := hex.DecodeString(config.Instance)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != config.Instance {
		return nil, errors.New("host instance must be 32 canonical hex bytes")
	}
	if !filepath.IsAbs(config.Executable) {
		return nil, errors.New("host executable must be an absolute path")
	}
	for _, duration := range []time.Duration{config.ReadinessTimeout, config.OperationTimeout, config.StopTimeout} {
		if duration <= 0 || duration > 30*time.Second {
			return nil, errors.New("host timeouts must be positive and at most 30 seconds")
		}
	}
	p, err := launch(config)
	if err != nil {
		return nil, err
	}
	return &Child{config: config, state: Candidate, process: p}, nil
}

func (c *Child) State() State     { c.mu.Lock(); defer c.mu.Unlock(); return c.state }
func (c *Child) CanCollect() bool { return c.State() == Stopped }

func (c *Child) AwaitReady() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != Candidate {
		return errors.New("host is not a candidate")
	}
	if err := c.exchange("", "ready", c.config.ReadinessTimeout); err != nil {
		return c.failed(err)
	}
	c.state = Ready
	return nil
}

func (c *Child) Activate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != Ready {
		return errors.New("host is not ready for activation")
	}
	if err := c.exchange("activate", "active", c.config.OperationTimeout); err != nil {
		return c.failed(err)
	}
	c.state = Active
	return nil
}

func (c *Child) Health() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != Active && c.state != Healthy {
		return errors.New("host is not active")
	}
	if err := c.exchange("health", "healthy", c.config.OperationTimeout); err != nil {
		return c.failed(err)
	}
	c.state = Healthy
	return nil
}

func (c *Child) exchange(command, expect string, limit time.Duration) error {
	m, err := c.exchangeMessage(context.Background(), command, expect, "", limit)
	if err == nil && m.Payload != "" {
		return errors.New("unexpected control payload")
	}
	return err
}

// Request runs one bounded operation in an already healthy feature process.
// The lifecycle owner admits the selected module and its permission first.
func (c *Child) Request(ctx context.Context, operation string, payload []byte, limit time.Duration) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != Healthy {
		return nil, errors.New("host is not healthy")
	}
	if operation == "" || len(operation) > 128 || len(payload) > MaxPayload || limit <= 0 || limit > 30*time.Second {
		return nil, errors.New("invalid feature request")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := c.exchangeMessage(ctx, "request:"+operation, "result:"+operation, base64.RawURLEncoding.EncodeToString(payload), limit)
	if err != nil {
		return nil, c.failed(err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(m.Payload)
	if err != nil || len(raw) > MaxPayload || base64.RawURLEncoding.EncodeToString(raw) != m.Payload {
		return nil, c.failed(errors.New("invalid feature response"))
	}
	return raw, nil
}

func (c *Child) exchangeMessage(ctx context.Context, command, expect, payload string, limit time.Duration) (Message, error) {
	if command != "" {
		if c.sequence == ^uint64(0) {
			return Message{}, errors.New("host control sequence exhausted")
		}
		c.sequence++
	}
	sequence := c.sequence
	type outcome struct {
		message Message
		err     error
	}
	done := make(chan outcome, 1)
	input, output := c.process.input(), c.process.output()
	go func() {
		if command != "" {
			if err := WriteMessage(input, Message{Version: 1, Type: command, Instance: c.config.Instance, Sequence: sequence, Payload: payload}); err != nil {
				done <- outcome{err: err}
				return
			}
		}
		m, err := ReadMessage(output)
		if err == nil && (m.Type != expect || m.Instance != c.config.Instance || m.Sequence != sequence) {
			err = errors.New("unexpected host response")
		}
		done <- outcome{m, err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.message, result.err
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-timer.C:
		return Message{}, fmt.Errorf("host %s timeout", expect)
	}
}

func (c *Child) waitEmpty() error {
	deadline := time.Now().Add(c.config.StopTimeout)
	for {
		empty, err := c.process.empty()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrContainment, err)
		}
		if empty {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrContainment
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *Child) forcedStop() error {
	if err := c.process.terminate(); err != nil {
		c.state = ContainmentUnknown
		return fmt.Errorf("%w: %v", ErrContainment, err)
	}
	if err := c.waitEmpty(); err != nil {
		c.state = ContainmentUnknown
		return err
	}
	c.state = Stopped
	return c.process.close()
}

func (c *Child) failed(cause error) error {
	if err := c.forcedStop(); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (c *Child) Stop() (StopResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == Stopped {
		return StopResult{}, nil
	}
	if c.state == ContainmentUnknown {
		return StopResult{}, ErrContainment
	}
	if err := c.exchange("stop", "stopped", c.config.StopTimeout); err == nil {
		if err = c.waitEmpty(); err == nil {
			c.state = Stopped
			return StopResult{}, c.process.close()
		}
	}
	return StopResult{Forced: true}, c.forcedStop()
}
