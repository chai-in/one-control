package ownership

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

const (
	lockFileFailImmediately = 1
	lockFileExclusive       = 2
	errorLockViolation      = syscall.Errno(33)
)

func open(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func tryLock(f *os.File) (bool, error) {
	var ov syscall.Overlapped
	r, _, err := lockFileEx.Call(f.Fd(), lockFileFailImmediately|lockFileExclusive, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if r != 0 {
		return false, nil
	}
	if errors.Is(err, errorLockViolation) {
		return true, nil
	}
	return false, fmt.Errorf("LockFileEx: %w", err)
}
