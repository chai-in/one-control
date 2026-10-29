//go:build !windows

package protectedstore

import "errors"

var errUnsupported = errors.New("protected_machine_storage_unsupported")

func Check(string, bool) error      { return errUnsupported }
func Create(string) error           { return errUnsupported }
func replace(string, string) error  { return errUnsupported }
func seal([]byte) ([]byte, error)   { return nil, errUnsupported }
func unseal([]byte) ([]byte, error) { return nil, errUnsupported }
