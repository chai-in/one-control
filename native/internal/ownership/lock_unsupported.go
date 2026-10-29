//go:build !windows && !linux && !darwin

package ownership

import (
	"errors"
	"os"
)

func open(string) (*os.File, error) {
	return nil, errors.New("native ownership is unsupported on this platform")
}
func tryLock(*os.File) (bool, error) {
	return false, errors.New("native ownership is unsupported on this platform")
}
