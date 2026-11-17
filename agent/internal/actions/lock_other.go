//go:build !linux

package actions

func (e Executor) lockNetwork() func() { return func() {} }
