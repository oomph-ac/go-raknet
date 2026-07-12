package internal

import (
	"encoding/binary"
	"hash/crc32"
	"net"
)

func Cookie(addr *net.UDPAddr, salt uint64) uint32 {
	b := make([]byte, 10, 26)
	binary.LittleEndian.PutUint64(b, salt)
	binary.LittleEndian.PutUint16(b[8:], uint16(addr.Port))
	b = append(b, addr.IP...)
	return crc32.ChecksumIEEE(b)
}
