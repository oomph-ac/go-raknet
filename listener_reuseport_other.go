//go:build !linux

package raknet

import (
	"fmt"
	"net"
)

func listenPacketConnsDefault(network, address string, socketCount int) ([]net.PacketConn, error) {
	if socketCount != 1 {
		return nil, fmt.Errorf("ReusePortSockets requires linux when UpstreamPacketListener is not set")
	}
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return []net.PacketConn{conn}, nil
}
