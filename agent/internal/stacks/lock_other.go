//go:build !linux

package stacks

import "context"

func lockGuard(context.Context) (func(), error) {
	return func() {}, nil
}
