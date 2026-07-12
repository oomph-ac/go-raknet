package raknet

import "net/netip"

type xdpFilter interface {
	RegisterConnection(addr netip.AddrPort) error
	UnregisterConnection(addr netip.AddrPort) error
}

var filter xdpFilter

func SetXDPFilter(f xdpFilter) {
	filter = f
}
