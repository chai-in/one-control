package ownership

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

type Owner struct {
	mu   sync.Mutex
	file *os.File
}

func Acquire(ctx context.Context, path string) (*Owner, error) {
	return acquire(ctx, path, open)
}

func acquisitionError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, bounded := ctx.Deadline(); bounded && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func acquire(ctx context.Context, path string, opener func(string) (*os.File, error)) (*Owner, error) {
	if err := acquisitionError(ctx); err != nil {
		return nil, err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("ownership acquisition requires a deadline")
	}
	f, err := opener(path)
	if err != nil {
		return nil, err
	}
	for {
		if err = acquisitionError(ctx); err != nil {
			f.Close()
			return nil, err
		}
		busy, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if !busy {
			if err = acquisitionError(ctx); err != nil {
				f.Close()
				return nil, err
			}
			return &Owner{file: f}, nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (o *Owner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.file == nil {
		return nil
	}
	err := o.file.Close()
	o.file = nil
	return err
}
