//go:build windows

package pipe

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

const (
	descriptor = "O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)"
	clients    = 8
)

func Serve(ctx context.Context, backend Backend) error {
	security, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return err
	}
	listener, err := (&namedpipe.ListenConfig{SecurityDescriptor: security}).Listen(Path)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	busy := make(chan struct{}, clients)
	for {
		select {
		case busy <- struct{}{}:
		case <-ctx.Done():
			listener.Close()
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			listener.Close()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer func() { <-busy }()
			defer conn.Close()
			Converse(conn, backend, time.Now)
		}()
	}
}
