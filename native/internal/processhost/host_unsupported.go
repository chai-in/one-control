//go:build !windows

package processhost

func launch(Config) (process, error) { return nil, ErrUnsupported }
