//go:build !windows

package indexing

func openSearch(bool) (provider, error) { return nil, errUnsupported }
