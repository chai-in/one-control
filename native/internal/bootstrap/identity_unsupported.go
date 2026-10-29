//go:build !windows

package bootstrap

import "errors"

func MachineID() (string, error) { return "", errors.New("machine_identity_unsupported") }
