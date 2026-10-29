//go:build !windows

package bootstrap

import "errors"

func (installation *Installation) Service() error { return errors.New("native_service_unsupported") }
