//go:build linux

package raknet

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenPacketConnsDefault(network, address string, socketCount int) ([]net.PacketConn, error) {
	if socketCount == 1 {
		conn, err := net.ListenPacket(network, address)
		if err != nil {
			return nil, err
		}
		return []net.PacketConn{conn}, nil
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					controlErr = fmt.Errorf("set SO_REUSEADDR: %w", err)
					return
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					controlErr = fmt.Errorf("set SO_REUSEPORT: %w", err)
				}
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	return openPacketConns(socketCount, address, func(bindAddress string) (net.PacketConn, error) {
		return lc.ListenPacket(context.Background(), network, bindAddress)
	})
}
