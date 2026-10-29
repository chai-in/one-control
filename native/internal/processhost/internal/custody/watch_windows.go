package custody

import (
	"fmt"
	"syscall"
)

type writerProcess struct{ handle syscall.Handle }

func (p *writerProcess) dead() (bool, error) {
	n, err := syscall.WaitForSingleObject(p.handle, 0)
	if err != nil {
		return true, err
	}
	switch n {
	case syscall.WAIT_OBJECT_0:
		return true, nil
	case syscall.WAIT_TIMEOUT:
		return false, nil
	}
	return true, fmt.Errorf("unexpected process wait result %d", n)
}

func (p *writerProcess) watch(stop <-chan struct{}) error {
	// A finite wait lets graceful teardown join this watcher without closing its retained process handle underneath it.
	for {
		n, err := syscall.WaitForSingleObject(p.handle, 10)
		if err != nil {
			return err
		}
		if n == syscall.WAIT_OBJECT_0 {
			return nil
		}
		if n != syscall.WAIT_TIMEOUT {
			return fmt.Errorf("unexpected writer wait result %d", n)
		}
		select {
		case <-stop:
			return nil
		default:
		}
	}
}
