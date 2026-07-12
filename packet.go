package raknet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// bitFlagDatagram is set for every valid datagram. It is used to identify
	// packets that are datagrams.
	bitFlagDatagram = 0b10000000
	// bitFlagACK is set for every ACK packet.
	bitFlagACK = 0b01000000
	// bitFlagHasBAndAS - seems to share the same bit with bitFlagNACK
	bitFlagHasBAndAS = 0b00100000
	// bitFlagNACK is set for every NACK packet.
	bitFlagNACK = 0b00100000
	// bitFlagPacketPair ...
	bitFlagPacketPair = 0b00010000
	// bitFlagContinuousSend ...
	bitFlagContinuousSend = 0b00001000
	// bitFlagNeedsBAndAS is set for every datagram with packet data, but is not
	// actually used.
	bitFlagNeedsBAndAS = 0b00000100
)

// noinspection GoUnusedConst
const (
	// reliabilityUnreliable means that the packet sent could arrive out of
	// order, be duplicated, or just not arrive at all. It is usually used for
	// high frequency packets of which the order does not matter.
	reliabilityUnreliable byte = iota
	// reliabilityUnreliableSequenced means that the packet sent could be
	// duplicated or not arrive at all, but ensures that it is always handled in
	// the right order.
	reliabilityUnreliableSequenced
	// reliabilityReliable means that the packet sent could not arrive, or
	// arrive out of order, but ensures that the packet is not duplicated.
	reliabilityReliable
	// reliabilityReliableOrdered means that every packet sent arrives, arrives
	// in the right order and is not duplicated.
	reliabilityReliableOrdered
	// reliabilityReliableSequenced means that the packet sent could not arrive,
	// but ensures that the packet will be in the right order and not be
	// duplicated.
	reliabilityReliableSequenced
)

// Exported reliability constants for use with WriteWithReliability.
const (
	// ReliabilityUnreliable means that the packet sent could arrive out of
	// order, be duplicated, or just not arrive at all. It is usually used for
	// high frequency packets of which the order does not matter.
	ReliabilityUnreliable = reliabilityUnreliable
	// ReliabilityUnreliableSequenced means that the packet sent could be
	// duplicated or not arrive at all, but ensures that it is always handled in
	// the right order.
	ReliabilityUnreliableSequenced = reliabilityUnreliableSequenced
	// ReliabilityReliable means that the packet sent could not arrive, or
	// arrive out of order, but ensures that the packet is not duplicated.
	ReliabilityReliable = reliabilityReliable
	// ReliabilityReliableOrdered means that every packet sent arrives, arrives
	// in the right order and is not duplicated.
	ReliabilityReliableOrdered = reliabilityReliableOrdered
	// ReliabilityReliableSequenced means that the packet sent could not arrive,
	// but ensures that the packet will be in the right order and not be
	// duplicated.
	ReliabilityReliableSequenced = reliabilityReliableSequenced
)

// packet is an encapsulation around every packet sent after the connection is
// established.
type packet struct {
	reliability byte

	messageIndex  uint24
	sequenceIndex uint24
	orderIndex    uint24

	content []byte

	split      bool
	splitCount uint32
	splitIndex uint32
	splitID    uint16
}

// write writes the packet and its content to the buffer passed.
func (pk *packet) write(buf *bytes.Buffer) {
	header := pk.reliability << 5
	if pk.split {
		header |= bitFlagPacketPair
	}

	buf.WriteByte(header)
	writeUint16(buf, uint16(len(pk.content))<<3)
	if pk.reliable() {
		writeUint24(buf, pk.messageIndex)
	}
	if pk.sequenced() {
		writeUint24(buf, pk.sequenceIndex)
	}
	if pk.sequencedOrOrdered() {
		writeUint24(buf, pk.orderIndex)
		// Order channel, we don't care about this.
		buf.WriteByte(0)
	}
	if pk.split {
		writeUint32(buf, pk.splitCount)
		writeUint16(buf, pk.splitID)
		writeUint32(buf, pk.splitIndex)
	}
	buf.Write(pk.content)
}

// read reads a packet and its content from the buffer passed.
func (pk *packet) read(b []byte) (int, error) {
	if len(b) < 3 {
		return 0, io.ErrUnexpectedEOF
	}
	header := b[0]
	pk.split = (header & bitFlagPacketPair) != 0
	pk.reliability = (header & 224) >> 5

	n := binary.BigEndian.Uint16(b[1:]) >> 3
	if n == 0 {
		return 0, errors.New("invalid packet length: cannot be 0")
	}
	offset := 3

	if pk.reliable() {
		if len(b)-offset < 3 {
			return 0, io.ErrUnexpectedEOF
		}
		pk.messageIndex = loadUint24(b[offset:])
		offset += 3
	}

	if pk.sequenced() {
		if len(b)-offset < 3 {
			return 0, io.ErrUnexpectedEOF
		}
		pk.sequenceIndex = loadUint24(b[offset:])
		offset += 3
	}

	if pk.sequencedOrOrdered() {
		if len(b)-offset < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		pk.orderIndex = loadUint24(b[offset:])
		// Order channel (byte)
		offset += 4
	}

	if pk.split {
		if len(b)-offset < 10 {
			return 0, io.ErrUnexpectedEOF
		}
		pk.splitCount = binary.BigEndian.Uint32(b[offset:])
		pk.splitID = binary.BigEndian.Uint16(b[offset+4:])
		pk.splitIndex = binary.BigEndian.Uint32(b[offset+6:])
		offset += 10
	}

	pk.content = make([]byte, n)
	if got := copy(pk.content, b[offset:]); got != int(n) {
		return 0, io.ErrUnexpectedEOF
	}
	return offset + int(n), nil
}

func (pk *packet) reliable() bool {
	switch pk.reliability {
	case reliabilityReliable,
		reliabilityReliableOrdered,
		reliabilityReliableSequenced:
		return true
	default:
		return false
	}
}

func (pk *packet) sequencedOrOrdered() bool {
	switch pk.reliability {
	case reliabilityUnreliableSequenced,
		reliabilityReliableOrdered,
		reliabilityReliableSequenced:
		return true
	default:
		return false
	}
}

func (pk *packet) sequenced() bool {
	switch pk.reliability {
	case reliabilityUnreliableSequenced,
		reliabilityReliableSequenced:
		return true
	default:
		return false
	}
}

const (
	// Datagram header +
	// Datagram sequence number +
	// Packet header +
	// Packet content length +
	// Packet message index +
	// Packet order index +
	// Packet order channel
	packetAdditionalSize = 1 + 3 + 1 + 2 + 3 + 3 + 1
	// Packet split count +
	// Packet split ID +
	// Packet split index
	splitAdditionalSize = 4 + 2 + 4
)

// split splits a content buffer in smaller buffers so that they do not exceed
// the MTU size that the connection holds.
func split(b []byte, mtu uint16) [][]byte {
	n := len(b)
	maxSize := int(mtu - packetAdditionalSize)

	if n > maxSize {
		// If the content size is bigger than the maximum size here, it means
		// the packet will get split. This means that the packet will get even
		// bigger because a split packet uses 4 + 2 + 4 more bytes.
		maxSize -= splitAdditionalSize
	}
	// If the content length can't be divided by maxSize perfectly, we need
	// to reserve another fragment for the last bit of the packet.
	fragmentCount := n/maxSize + min(n%maxSize, 1)
	fragments := make([][]byte, fragmentCount)
	for i := range fragmentCount - 1 {
		fragments[i] = b[:maxSize]
		b = b[maxSize:]
	}
	fragments[len(fragments)-1] = b
	return fragments
}
