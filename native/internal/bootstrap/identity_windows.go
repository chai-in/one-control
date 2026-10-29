package bootstrap

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"strings"
)

func MachineID() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("machine_identity_unavailable")
	}
	return "windows:" + strings.ToLower(value), nil
}
