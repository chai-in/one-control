package ownership

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsOwnerHandleDoesNotInherit(t *testing.T) {
	o, err := acquireTest(filepath.Join(t.TempDir(), "writer.lock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	var flags uint32
	r, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("GetHandleInformation").Call(o.file.Fd(), uintptr(unsafe.Pointer(&flags)))
	if r == 0 || flags&syscall.HANDLE_FLAG_INHERIT != 0 {
		t.Fatalf("ownership handle can inherit: flags=%d error=%v", flags, err)
	}
}
