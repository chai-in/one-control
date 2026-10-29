package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/ownership"
	"os"
	"reflect"
	"sync"
)

type Store struct {
	mu   sync.Mutex
	path string
	lock *ownership.Owner
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	lock, e := ownership.Acquire(ctx, path+".lock")
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, lock: lock}
	if _, e = s.Load(); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	e := s.lock.Close()
	s.lock = nil
	return e
}
func (s *Store) Load() (*contracts.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil, os.ErrClosed
	}
	return s.load()
}
func (s *Store) load() (*contracts.Checkpoint, error) {
	f, e := os.Open(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var prior *contracts.Checkpoint
	for {
		var size [4]byte
		_, e := io.ReadFull(f, size[:])
		if e == io.EOF {
			return prior, nil
		}
		if e != nil {
			return nil, fault("invalid_checkpoint")
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 || n > 8192 {
			return nil, fault("invalid_checkpoint")
		}
		payload := make([]byte, n)
		var digest [32]byte
		if _, e = io.ReadFull(f, payload); e != nil {
			return nil, fault("invalid_checkpoint")
		}
		if _, e = io.ReadFull(f, digest[:]); e != nil {
			return nil, fault("invalid_checkpoint")
		}
		sum := sha256.Sum256(payload)
		if !bytes.Equal(sum[:], digest[:]) {
			return nil, fault("invalid_checkpoint")
		}
		var cp contracts.Checkpoint
		if _, e = contracts.Decode(payload, "Checkpoint", &cp); e != nil {
			return nil, fault("invalid_checkpoint")
		}
		if e = advance(prior, cp); e != nil {
			return nil, e
		}
		prior = &cp
	}
}
func advance(prior *contracts.Checkpoint, next contracts.Checkpoint) error {
	if prior == nil {
		return nil
	}
	if prior.BindingDigest != next.BindingDigest || next.SeenAt < prior.SeenAt || number(next.RootVersion) < number(prior.RootVersion) || number(next.AuthorityEpoch) < number(prior.AuthorityEpoch) {
		return fault("invalid_checkpoint")
	}
	if next.AuthorityEpoch == prior.AuthorityEpoch {
		if number(next.Revision) < number(prior.Revision) || (next.Revision == prior.Revision && next.PolicyDigest != prior.PolicyDigest) {
			return fault("invalid_checkpoint")
		}
	} else if number(next.RootVersion) <= number(prior.RootVersion) {
		return fault("invalid_checkpoint")
	}
	if next.Nonce == prior.Nonce {
		return fault("invalid_checkpoint")
	}
	return nil
}
func (s *Store) Commit(expected *contracts.Checkpoint, next contracts.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return os.ErrClosed
	}
	current, e := s.load()
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(current, expected) {
		return fault("checkpoint_conflict")
	}
	payload, e := json.Marshal(next)
	if e != nil {
		return e
	}
	var valid contracts.Checkpoint
	if _, e = contracts.Decode(payload, "Checkpoint", &valid); e != nil {
		return e
	}
	if e = advance(current, next); e != nil {
		return e
	}
	f, e := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	frame = append(frame, payload...)
	sum := sha256.Sum256(payload)
	frame = append(frame, sum[:]...)
	n, e := f.Write(frame)
	if e == nil && n != len(frame) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	// Parent-directory durability on Windows requires its platform adapter. This
	// portable unit only claims a flushed append and detects torn frames.
	return e
}
