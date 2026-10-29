//go:build !windows

package sessions

import (
	"context"
	"errors"
)

func collect(context.Context) ([]Session, bool, error) {
	return nil, false, errors.New("platform_unsupported")
}
