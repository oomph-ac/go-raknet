//go:build !linux

package raknet

import "net"

func (listener *Listener) listenOptimized(net.PacketConn, chan<- listenerUnconnectedDatagram) bool {
	return false
}
