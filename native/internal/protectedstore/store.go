// Package protectedstore owns machine-private configuration and credentials.
package protectedstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func Read(path string, limit int64) ([]byte, error) {
	if err := Check(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("protected_file_too_large")
	}
	return data, nil
}

// Write commits a flushed replacement inside an already protected directory.
func Write(path string, data []byte) error {
	if err := Check(filepath.Dir(path), true); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = Check(path, true); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replace(name, path)
}

func ReadSecret(path string) ([]byte, error) {
	data, err := Read(path, 1<<20)
	if err != nil {
		return nil, err
	}
	return unseal(data)
}

func WriteSecret(path string, data []byte) error {
	sealed, err := seal(data)
	if err != nil {
		return err
	}
	return Write(path, sealed)
}
