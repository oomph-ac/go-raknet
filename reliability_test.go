package raknet

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
)

// TestPacket_WriteReadReliabilityUnreliable tests writing and reading an unreliable packet.
// Unreliable packets should not have messageIndex, sequenceIndex, or orderIndex.
func TestPacket_WriteReadReliabilityUnreliable(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability: reliabilityUnreliable,
		content:     content,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if read.reliability != reliabilityUnreliable {
		t.Fatalf("expected reliability %d, got %d", reliabilityUnreliable, read.reliability)
	}
	if !bytes.Equal(read.content, content) {
		t.Fatalf("expected content %v, got %v", content, read.content)
	}
	// Unreliable packets should not have any indices set during read
	if read.reliable() {
		t.Fatal("unreliable packet should not be marked as reliable")
	}
	if read.sequenced() {
		t.Fatal("unreliable packet should not be marked as sequenced")
	}
	if read.sequencedOrOrdered() {
		t.Fatal("unreliable packet should not be marked as sequenced or ordered")
	}
}

// TestPacket_WriteReadReliabilityUnreliableSequenced tests writing and reading an unreliable sequenced packet.
// Unreliable sequenced packets should have sequenceIndex and orderIndex, but not messageIndex.
func TestPacket_WriteReadReliabilityUnreliableSequenced(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability:   reliabilityUnreliableSequenced,
		sequenceIndex: 42,
		orderIndex:    100,
		content:       content,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if read.reliability != reliabilityUnreliableSequenced {
		t.Fatalf("expected reliability %d, got %d", reliabilityUnreliableSequenced, read.reliability)
	}
	if !bytes.Equal(read.content, content) {
		t.Fatalf("expected content %v, got %v", content, read.content)
	}
	if read.sequenceIndex != 42 {
		t.Fatalf("expected sequenceIndex 42, got %d", read.sequenceIndex)
	}
	if read.orderIndex != 100 {
		t.Fatalf("expected orderIndex 100, got %d", read.orderIndex)
	}
	if read.reliable() {
		t.Fatal("unreliable sequenced packet should not be marked as reliable")
	}
	if !read.sequenced() {
		t.Fatal("unreliable sequenced packet should be marked as sequenced")
	}
	if !read.sequencedOrOrdered() {
		t.Fatal("unreliable sequenced packet should be marked as sequenced or ordered")
	}
}

// TestPacket_WriteReadReliabilityReliable tests writing and reading a reliable packet.
// Reliable packets should have messageIndex, but not sequenceIndex or orderIndex.
func TestPacket_WriteReadReliabilityReliable(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability:  reliabilityReliable,
		messageIndex: 55,
		content:      content,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if read.reliability != reliabilityReliable {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliable, read.reliability)
	}
	if !bytes.Equal(read.content, content) {
		t.Fatalf("expected content %v, got %v", content, read.content)
	}
	if read.messageIndex != 55 {
		t.Fatalf("expected messageIndex 55, got %d", read.messageIndex)
	}
	if read.reliable() != true {
		t.Fatal("reliable packet should be marked as reliable")
	}
	if read.sequenced() {
		t.Fatal("reliable packet should not be marked as sequenced")
	}
	if read.sequencedOrOrdered() {
		t.Fatal("reliable packet should not be marked as sequenced or ordered")
	}
}

// TestPacket_WriteReadReliabilityReliableOrdered tests writing and reading a reliable ordered packet.
// Reliable ordered packets should have messageIndex and orderIndex, but not sequenceIndex.
func TestPacket_WriteReadReliabilityReliableOrdered(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability:  reliabilityReliableOrdered,
		messageIndex: 77,
		orderIndex:   200,
		content:      content,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if read.reliability != reliabilityReliableOrdered {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliableOrdered, read.reliability)
	}
	if !bytes.Equal(read.content, content) {
		t.Fatalf("expected content %v, got %v", content, read.content)
	}
	if read.messageIndex != 77 {
		t.Fatalf("expected messageIndex 77, got %d", read.messageIndex)
	}
	if read.orderIndex != 200 {
		t.Fatalf("expected orderIndex 200, got %d", read.orderIndex)
	}
	if !read.reliable() {
		t.Fatal("reliable ordered packet should be marked as reliable")
	}
	if read.sequenced() {
		t.Fatal("reliable ordered packet should not be marked as sequenced")
	}
	if !read.sequencedOrOrdered() {
		t.Fatal("reliable ordered packet should be marked as sequenced or ordered")
	}
}

// TestPacket_WriteReadReliabilityReliableSequenced tests writing and reading a reliable sequenced packet.
// Reliable sequenced packets should have messageIndex, sequenceIndex, and orderIndex.
func TestPacket_WriteReadReliabilityReliableSequenced(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability:   reliabilityReliableSequenced,
		messageIndex:  88,
		sequenceIndex: 99,
		orderIndex:    300,
		content:       content,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if read.reliability != reliabilityReliableSequenced {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliableSequenced, read.reliability)
	}
	if !bytes.Equal(read.content, content) {
		t.Fatalf("expected content %v, got %v", content, read.content)
	}
	if read.messageIndex != 88 {
		t.Fatalf("expected messageIndex 88, got %d", read.messageIndex)
	}
	if read.sequenceIndex != 99 {
		t.Fatalf("expected sequenceIndex 99, got %d", read.sequenceIndex)
	}
	if read.orderIndex != 300 {
		t.Fatalf("expected orderIndex 300, got %d", read.orderIndex)
	}
	if !read.reliable() {
		t.Fatal("reliable sequenced packet should be marked as reliable")
	}
	if !read.sequenced() {
		t.Fatal("reliable sequenced packet should be marked as sequenced")
	}
	if !read.sequencedOrOrdered() {
		t.Fatal("reliable sequenced packet should be marked as sequenced or ordered")
	}
}

// TestPacket_WriteReadWithSplit tests that split flag is preserved across write/read.
func TestPacket_WriteReadWithSplit(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03, 0x04}

	original := &packet{
		reliability:  reliabilityReliableOrdered,
		messageIndex: 10,
		orderIndex:   20,
		content:      content,
		split:        true,
		splitCount:   5,
		splitID:      123,
		splitIndex:   2,
	}

	buf := bytes.NewBuffer(nil)
	original.write(buf)

	read := &packet{}
	n, err := read.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("expected to read %d bytes, got %d", buf.Len(), n)
	}

	if !read.split {
		t.Fatal("expected split flag to be true")
	}
	if read.splitCount != 5 {
		t.Fatalf("expected splitCount 5, got %d", read.splitCount)
	}
	if read.splitID != 123 {
		t.Fatalf("expected splitID 123, got %d", read.splitID)
	}
	if read.splitIndex != 2 {
		t.Fatalf("expected splitIndex 2, got %d", read.splitIndex)
	}
}

// TestConn_WriteWithReliability_ReliabilityUnreliable tests that WriteWithReliability
// correctly creates unreliable packets.
func TestConn_WriteWithReliability_ReliabilityUnreliable(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	n, err := conn.WriteWithReliability(content, ReliabilityUnreliable)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	// Parse the datagram to verify the packet structure
	if len(writtenData) < 4 {
		t.Fatalf("written data too short: %d", len(writtenData))
	}

	// Skip datagram header (1 byte) and sequence number (3 bytes)
	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	if pk.reliability != reliabilityUnreliable {
		t.Fatalf("expected reliability %d, got %d", reliabilityUnreliable, pk.reliability)
	}
	if !bytes.Equal(pk.content, content) {
		t.Fatalf("expected content %v, got %v", content, pk.content)
	}
}

// TestConn_WriteWithReliability_ReliabilityReliable tests that WriteWithReliability
// correctly creates reliable packets with messageIndex.
func TestConn_WriteWithReliability_ReliabilityReliable(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	n, err := conn.WriteWithReliability(content, ReliabilityReliable)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	// Parse the datagram to verify the packet structure
	if len(writtenData) < 4 {
		t.Fatalf("written data too short: %d", len(writtenData))
	}

	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	if pk.reliability != reliabilityReliable {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliable, pk.reliability)
	}
	if !bytes.Equal(pk.content, content) {
		t.Fatalf("expected content %v, got %v", content, pk.content)
	}
	// Reliable packets should have a messageIndex
	if !pk.reliable() {
		t.Fatal("reliable packet should be marked as reliable")
	}
}

// TestConn_WriteWithReliability_ReliabilityReliableOrdered tests that WriteWithReliability
// correctly creates reliable ordered packets with messageIndex and orderIndex.
func TestConn_WriteWithReliability_ReliabilityReliableOrdered(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	n, err := conn.WriteWithReliability(content, ReliabilityReliableOrdered)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	if pk.reliability != reliabilityReliableOrdered {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliableOrdered, pk.reliability)
	}
	if !bytes.Equal(pk.content, content) {
		t.Fatalf("expected content %v, got %v", content, pk.content)
	}
	if !pk.reliable() {
		t.Fatal("reliable ordered packet should be marked as reliable")
	}
	if !pk.sequencedOrOrdered() {
		t.Fatal("reliable ordered packet should be marked as ordered")
	}
}

// TestConn_WriteWithReliability_ReliabilityUnreliableSequenced tests that WriteWithReliability
// correctly creates unreliable sequenced packets with sequenceIndex and orderIndex.
func TestConn_WriteWithReliability_ReliabilityUnreliableSequenced(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	n, err := conn.WriteWithReliability(content, ReliabilityUnreliableSequenced)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	if pk.reliability != reliabilityUnreliableSequenced {
		t.Fatalf("expected reliability %d, got %d", reliabilityUnreliableSequenced, pk.reliability)
	}
	if !bytes.Equal(pk.content, content) {
		t.Fatalf("expected content %v, got %v", content, pk.content)
	}
	if pk.reliable() {
		t.Fatal("unreliable sequenced packet should not be marked as reliable")
	}
	if !pk.sequenced() {
		t.Fatal("unreliable sequenced packet should be marked as sequenced")
	}
	if !pk.sequencedOrOrdered() {
		t.Fatal("unreliable sequenced packet should be marked as ordered")
	}
}

// TestConn_WriteWithReliability_ReliabilityReliableSequenced tests that WriteWithReliability
// correctly creates reliable sequenced packets with all indices.
func TestConn_WriteWithReliability_ReliabilityReliableSequenced(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	n, err := conn.WriteWithReliability(content, ReliabilityReliableSequenced)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	if pk.reliability != reliabilityReliableSequenced {
		t.Fatalf("expected reliability %d, got %d", reliabilityReliableSequenced, pk.reliability)
	}
	if !bytes.Equal(pk.content, content) {
		t.Fatalf("expected content %v, got %v", content, pk.content)
	}
	if !pk.reliable() {
		t.Fatal("reliable sequenced packet should be marked as reliable")
	}
	if !pk.sequenced() {
		t.Fatal("reliable sequenced packet should be marked as sequenced")
	}
	if !pk.sequencedOrOrdered() {
		t.Fatal("reliable sequenced packet should be marked as ordered")
	}
}

// TestConn_WriteWithReliability_IndicesIncrement tests that indices are properly
// incremented across multiple writes.
func TestConn_WriteWithReliability_IndicesIncrement(t *testing.T) {
	var packets []*packet
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			pk := &packet{}
			if _, err := pk.read(p[4:]); err == nil {
				packets = append(packets, pk)
			}
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Write multiple reliable ordered packets
	for i := 0; i < 3; i++ {
		_, err := conn.WriteWithReliability([]byte{byte(i)}, ReliabilityReliableOrdered)
		if err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	// Check that orderIndex and messageIndex are incrementing
	// Inc() returns the old value, so first packet gets 0, second gets 1, etc.
	for i, pk := range packets {
		expectedOrderIndex := uint24(i)
		if pk.orderIndex != expectedOrderIndex {
			t.Fatalf("packet %d: expected orderIndex %d, got %d", i, expectedOrderIndex, pk.orderIndex)
		}
		expectedMessageIndex := uint24(i)
		if pk.messageIndex != expectedMessageIndex {
			t.Fatalf("packet %d: expected messageIndex %d, got %d", i, expectedMessageIndex, pk.messageIndex)
		}
	}
}

// TestConn_WriteWithReliability_SequenceIndexIncrement tests that sequenceIndex
// is properly incremented for sequenced packets.
func TestConn_WriteWithReliability_SequenceIndexIncrement(t *testing.T) {
	var packets []*packet
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			pk := &packet{}
			if _, err := pk.read(p[4:]); err == nil {
				packets = append(packets, pk)
			}
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Write multiple reliable sequenced packets
	for i := 0; i < 3; i++ {
		_, err := conn.WriteWithReliability([]byte{byte(i)}, ReliabilityReliableSequenced)
		if err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	// Check that sequenceIndex is incrementing
	// Inc() returns the old value, so first packet gets 0, second gets 1, etc.
	for i, pk := range packets {
		expectedSequenceIndex := uint24(i)
		if pk.sequenceIndex != expectedSequenceIndex {
			t.Fatalf("packet %d: expected sequenceIndex %d, got %d", i, expectedSequenceIndex, pk.sequenceIndex)
		}
	}
}

// TestConn_WriteWithReliability_MixedReliabilities tests that different reliability
// types can be used on the same connection without interfering.
func TestConn_WriteWithReliability_MixedReliabilities(t *testing.T) {
	var packets []*packet
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			pk := &packet{}
			if _, err := pk.read(p[4:]); err == nil {
				packets = append(packets, pk)
			}
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Write with different reliabilities
	reliabilities := []byte{
		ReliabilityUnreliable,
		ReliabilityReliable,
		ReliabilityReliableOrdered,
		ReliabilityUnreliableSequenced,
		ReliabilityReliableSequenced,
	}

	for i, rel := range reliabilities {
		_, err := conn.WriteWithReliability([]byte{byte(i)}, rel)
		if err != nil {
			t.Fatalf("write with reliability %d failed: %v", rel, err)
		}
	}

	if len(packets) != len(reliabilities) {
		t.Fatalf("expected %d packets, got %d", len(reliabilities), len(packets))
	}

	// Verify each packet has the correct reliability
	for i, pk := range packets {
		if pk.reliability != reliabilities[i] {
			t.Fatalf("packet %d: expected reliability %d, got %d", i, reliabilities[i], pk.reliability)
		}
	}
}

// TestConn_Write_BackwardsCompatibility tests that the default Write function
// still uses ReliabilityReliableOrdered for backwards compatibility.
func TestConn_Write_BackwardsCompatibility(t *testing.T) {
	var writtenData []byte
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (int, error) {
			writtenData = make([]byte, len(p))
			copy(writtenData, p)
			return len(p), nil
		},
	}

	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})
	content := []byte{0xAA, 0xBB, 0xCC}

	// Use the default Write function
	n, err := conn.Write(content)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(content) {
		t.Fatalf("expected to write %d bytes, got %d", len(content), n)
	}

	pk := &packet{}
	_, err = pk.read(writtenData[4:])
	if err != nil {
		t.Fatalf("failed to read packet from written data: %v", err)
	}

	// Default Write should use reliabilityReliableOrdered
	if pk.reliability != reliabilityReliableOrdered {
		t.Fatalf("expected reliability %d (reliableOrdered), got %d", reliabilityReliableOrdered, pk.reliability)
	}
}

// TestReliabilityConstants_Exported tests that the exported reliability constants
// match their internal counterparts.
func TestReliabilityConstants_Exported(t *testing.T) {
	if ReliabilityUnreliable != reliabilityUnreliable {
		t.Fatal("ReliabilityUnreliable does not match internal constant")
	}
	if ReliabilityUnreliableSequenced != reliabilityUnreliableSequenced {
		t.Fatal("ReliabilityUnreliableSequenced does not match internal constant")
	}
	if ReliabilityReliable != reliabilityReliable {
		t.Fatal("ReliabilityReliable does not match internal constant")
	}
	if ReliabilityReliableOrdered != reliabilityReliableOrdered {
		t.Fatal("ReliabilityReliableOrdered does not match internal constant")
	}
	if ReliabilityReliableSequenced != reliabilityReliableSequenced {
		t.Fatal("ReliabilityReliableSequenced does not match internal constant")
	}
}

// TestPacket_ReliableMethod tests the reliable() method for all reliability types.
func TestPacket_ReliableMethod(t *testing.T) {
	tests := []struct {
		reliability byte
		expected    bool
	}{
		{reliabilityUnreliable, false},
		{reliabilityUnreliableSequenced, false},
		{reliabilityReliable, true},
		{reliabilityReliableOrdered, true},
		{reliabilityReliableSequenced, true},
	}

	for _, tt := range tests {
		pk := &packet{reliability: tt.reliability}
		if pk.reliable() != tt.expected {
			t.Fatalf("reliability %d: expected reliable() = %v, got %v", tt.reliability, tt.expected, pk.reliable())
		}
	}
}

// TestPacket_SequencedMethod tests the sequenced() method for all reliability types.
func TestPacket_SequencedMethod(t *testing.T) {
	tests := []struct {
		reliability byte
		expected    bool
	}{
		{reliabilityUnreliable, false},
		{reliabilityUnreliableSequenced, true},
		{reliabilityReliable, false},
		{reliabilityReliableOrdered, false},
		{reliabilityReliableSequenced, true},
	}

	for _, tt := range tests {
		pk := &packet{reliability: tt.reliability}
		if pk.sequenced() != tt.expected {
			t.Fatalf("reliability %d: expected sequenced() = %v, got %v", tt.reliability, tt.expected, pk.sequenced())
		}
	}
}

// TestPacket_SequencedOrOrderedMethod tests the sequencedOrOrdered() method for all reliability types.
func TestPacket_SequencedOrOrderedMethod(t *testing.T) {
	tests := []struct {
		reliability byte
		expected    bool
	}{
		{reliabilityUnreliable, false},
		{reliabilityUnreliableSequenced, true},
		{reliabilityReliable, false},
		{reliabilityReliableOrdered, true},
		{reliabilityReliableSequenced, true},
	}

	for _, tt := range tests {
		pk := &packet{reliability: tt.reliability}
		if pk.sequencedOrOrdered() != tt.expected {
			t.Fatalf("reliability %d: expected sequencedOrOrdered() = %v, got %v", tt.reliability, tt.expected, pk.sequencedOrOrdered())
		}
	}
}
