package raknet

import (
	"bytes"
)

// uint24 represents an integer existing out of 3 bytes. It is actually a
// uint32, but is an alias for the sake of clarity.
type uint24 uint32

// Inc increments a uint24 and returns the old value.
func (u *uint24) Inc() (old uint24) {
	ret := *u
	*u += 1
	return ret
}

// loadUint24 interprets the first 3 bytes in b as a uint24.
func loadUint24(b []byte) uint24 {
	return uint24(b[0]) | (uint24(b[1]) << 8) | (uint24(b[2]) << 16)
}

// writeUint24 writes a uint24 to the buffer passed as 3 bytes. If not
// successful, an error is returned.
func writeUint24(b *bytes.Buffer, v uint24) {
	b.Write([]byte{
		byte(v),
		byte(v >> 8),
		byte(v >> 16),
	})
}

func writeUint16(b *bytes.Buffer, v uint16) {
	b.Write([]byte{
		byte(v >> 8),
		byte(v),
	})
}

func writeUint32(b *bytes.Buffer, v uint32) {
	b.Write([]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}
