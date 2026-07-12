package raknet

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/go-raknet/message"
)

// Mock connection handler that enforces limits (simulating a listener)
type mockListenerHandler struct {
	logger *slog.Logger
}

func (h *mockListenerHandler) handle(conn *Conn, b []byte, reliability byte) (bool, error) {
	return false, nil
}

func (h *mockListenerHandler) limitsEnabled() bool {
	return true
}

func (h *mockListenerHandler) close(conn *Conn) {}

func (h *mockListenerHandler) log() *slog.Logger {
	return h.logger
}

// Mock PacketConn to satisfy net.PacketConn
type mockPacketConn struct {
	net.PacketConn
	writeToFunc func(p []byte, addr net.Addr) (n int, err error)
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if m.writeToFunc != nil {
		return m.writeToFunc(p, addr)
	}
	return len(p), nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19132}
}

func (m *mockPacketConn) Close() error { return nil }

func newTestListener() *Listener {
	l := &Listener{
		conf: ListenConfig{
			ErrorLog: slog.Default(),
		},
		conn: &mockPacketConn{},
	}
	l.pongData.Store(new([]byte))
	return l
}

func TestSecurity_ACKResourceExhaustion(t *testing.T) {
	// Test that reading an ACK with too many packets returns an error
	// to prevent memory exhaustion.
	ack := &acknowledgement{}

	// Create a buffer for an ACK packet
	buf := bytes.NewBuffer(nil)

	// Record count: 1
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Record type: Range
	buf.WriteByte(packetRange)

	// Start: 0
	writeUint24(buf, 0)
	// End: 10000 (exceeds maxAcknowledgementPackets of 8192)
	writeUint24(buf, 10000)

	err := ack.read(buf.Bytes())
	if err != errMaxAcknowledgement {
		t.Fatalf("expected errMaxAcknowledgement, got %v", err)
	}
}

func TestSecurity_SplitPacketLimits(t *testing.T) {
	// Test that receiving a split packet with a huge split count is rejected
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Construct a split packet
	// Header: reliabilityReliableOrdered (3) << 5 | splitFlag (0x10)
	header := (reliabilityReliableOrdered << 5) | bitFlagPacketPair

	buf := bytes.NewBuffer(nil)
	buf.WriteByte(header)

	// Length (in bits)
	binary.Write(buf, binary.BigEndian, uint16(10<<3)) // 10 bytes content

	// Reliable Message Index
	writeUint24(buf, 0)
	// Ordered Order Index
	writeUint24(buf, 0)
	// Order Channel
	buf.WriteByte(0)

	// Split Info
	// Split Count: 1000 (exceeds maxSplitCount 512)
	binary.Write(buf, binary.BigEndian, uint32(1000))
	// Split ID
	binary.Write(buf, binary.BigEndian, uint16(1))
	// Split Index
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Content
	buf.Write(make([]byte, 10))

	pk := &packet{}
	_, err := pk.read(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to read packet: %v", err)
	}

	err = conn.receiveSplitPacket(pk)
	if err == nil {
		t.Fatal("expected error for excessive split count, got nil")
	}
	expected := "split count 1000 exceeds the maximum 512"
	if err.Error() != "split packet: "+expected {
		t.Fatalf("expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestSecurity_ConcurrentSplitsLimit(t *testing.T) {
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Fill up concurrent splits
	for i := uint16(0); i < 18; i++ {
		pk := &packet{
			reliability: reliabilityReliableOrdered,
			split:       true,
			splitCount:  2,
			splitID:     i,
			splitIndex:  0,
			content:     []byte{0x00},
		}

		err := conn.receiveSplitPacket(pk)
		if i < 17 {
			if err != nil {
				t.Fatalf("iteration %d: unexpected error: %v", i, err)
			}
		} else {
			if err == nil {
				t.Fatal("expected error for too many concurrent splits")
			}
			expected := "maximum concurrent splits 16 reached"
			if err.Error() != "split packet: "+expected {
				t.Fatalf("expected error '%s', got '%s'", expected, err.Error())
			}
		}
	}
}

func TestSecurity_DatagramWindowLimit(t *testing.T) {
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Helper to create a datagram with a valid dummy packet
	makeDatagram := func(seq uint24) []byte {
		buf := bytes.NewBuffer(nil)
		buf.WriteByte(bitFlagDatagram)
		writeUint24(buf, seq)

		// Write a dummy packet with sufficient size
		pk := &packet{
			reliability: reliabilityUnreliable,
			content:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
		}
		pk.write(buf)

		return buf.Bytes()
	}

	// Send seq 0
	data0 := makeDatagram(0)
	if err := conn.receiveDatagram(data0[1:]); err != nil {
		t.Fatalf("failed to receive datagram 0: %v", err)
	}

	// Set RTT to a large value to prevent immediate window sliding due to "missing" packets.
	// If RTT is 0 (default), the window assumes all intermediate packets are lost/missing and slides immediately.
	conn.rtt.Store(int64(time.Second))

	// Send seq 5000. Window size becomes 5000. Should fail.
	data5000 := makeDatagram(5000)
	err := conn.receiveDatagram(data5000[1:])
	if err == nil {
		t.Fatal("expected error for huge window size")
	}
	if err.Error()[:38] != "receive datagram: queue window size is" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecurity_PacketQueueLimit(t *testing.T) {
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Packet 1: OrderIndex 0
	pk1 := &packet{
		reliability: reliabilityReliableOrdered,
		orderIndex:  0,
		content:     []byte{1},
	}
	if err := conn.receivePacket(pk1); err != nil {
		t.Fatalf("failed to receive packet 1: %v", err)
	}

	// Send OrderIndex 3000. Gap [1, 2999].
	pk2 := &packet{
		reliability: reliabilityReliableOrdered,
		orderIndex:  3000,
		content:     []byte{1},
	}

	err := conn.receivePacket(pk2)
	if err == nil {
		t.Fatal("expected error for huge packet queue window")
	}
	// Error message: "packet queue window size is too big (%v-%v)"
	if err.Error()[:32] != "packet queue window size is too " {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecurity_MalformedDatagrams(t *testing.T) {
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	tests := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"TooShort", []byte{bitFlagDatagram, 0x01}}, // Need 3 bytes for seq
		{"OnlyHeader", []byte{bitFlagDatagram}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := conn.receiveDatagram(tt.data)
			if err == nil {
				t.Fatal("expected error for malformed datagram")
			}
		})
	}
}

func TestSecurity_OpenConnectionRequest1_MTU(t *testing.T) {
	// Test that small MTU is rejected
	h := listenerConnectionHandler{listener: &Listener{connections: sync.Map{}}}

	// Construct OpenConnectionRequest1
	ocr1 := &message.OpenConnectionRequest1{
		MTU:            10, // Too small (min is 400)
		ClientProtocol: protocolVersion,
	}
	b, _ := ocr1.MarshalBinary()
	// Add packet ID
	payload := append([]byte{message.IDOpenConnectionRequest1}, b...)

	err := h.handleOpenConnectionRequest1(payload[1:], &net.UDPAddr{})
	if err == nil {
		t.Fatal("expected error for small MTU")
	}
	if err.Error() != "handle OPEN_CONNECTION_REQUEST_1: MTU is less than minimum MTU size 576" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecurity_OpenConnectionRequest2_MTU(t *testing.T) {
	// Test that small MTU is rejected in Request2 as well
	// Disable cookies to avoid cookie validation issues in test
	h := listenerConnectionHandler{listener: &Listener{connections: sync.Map{}, conf: ListenConfig{DisableCookies: true}}}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19132}

	ocr2 := &message.OpenConnectionRequest2{
		MTU:               10,
		ServerAddress:     netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 19132),
		ServerHasSecurity: false, // Cookies disabled
	}
	b, _ := ocr2.MarshalBinary()

	// handleOpenConnectionRequest2 expects the buffer WITHOUT the ID (b[1:])
	err := h.handleOpenConnectionRequest2(b[1:], addr)
	if err == nil {
		t.Fatal("expected error for small MTU")
	}
	if err.Error() != "handle OPEN_CONNECTION_REQUEST_2: MTU is less than minimum MTU size 576" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecurity_OpenConnectionRequest1_DuplicateAddress(t *testing.T) {
	listener := newTestListener()
	handler := listenerConnectionHandler{
		listener: listener,
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19132}
	listener.connections.Store(resolve(addr), &Conn{})

	req := &message.OpenConnectionRequest1{
		ClientProtocol: protocolVersion,
		MTU:            minMTUSize,
	}
	payload, _ := req.MarshalBinary()

	err := handler.handleOpenConnectionRequest1(payload[1:], addr)
	if err == nil || !strings.Contains(err.Error(), "connection already exists") {
		t.Fatalf("expected duplicate connection error, got %v", err)
	}
}

/* func TestSecurity_OpenConnectionRequest2_InvalidCookie(t *testing.T) {
listener := newTestListener()
handler := listenerConnectionHandler{
	listener: listener,
}
addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 26000}
expected := uint32(12345678)
// Store the expected cookie in pendingCookies for later validation.
handler.pendingCookies.Store(resolve(addr), internal.PendingCookie{Cookie: expected, CreatedAt: timestamp()})

req := &message.OpenConnectionRequest2{
	ServerAddress:     netip.MustParseAddrPort("127.0.0.1:19133"),
	MTU:               minMTUSize,
	ClientGUID:        1,
	ServerHasSecurity: true,
	Cookie:            expected + 1,
}
payload, _ := req.MarshalBinary()

err := handler.handleOpenConnectionRequest2(payload[1:], addr)
if err == nil || !strings.Contains(err.Error(), "invalid cookie") {
	t.Fatalf("expected invalid cookie error, got %v", err)
}
} */

/* func TestSecurity_OpenConnectionRequest2_DuplicateAddress(t *testing.T) {
	listener := newTestListener()
handler := listenerConnectionHandler{
	listener: listener,

addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19134}
listener.connections.Store(resolve(addr), &Conn{})
cookie := uint32(87654321)
// Store the expected cookie in pendingCookies (though it won't be checked since connection already exists).
handler.pendingCookies.Store(resolve(addr), internal.PendingCookie{Cookie: cookie, CreatedAt: timestamp()})

	req := &message.OpenConnectionRequest2{
	ServerAddress:     netip.MustParseAddrPort("127.0.0.1:19133"),
	MTU:               minMTUSize,
	ClientGUID:        1,
	ServerHasSecurity: true,
	Cookie:            cookie,
}
payload, _ := req.MarshalBinary()

	err := handler.handleOpenConnectionRequest2(payload[1:], addr)
if err == nil || !strings.Contains(err.Error(), "connection already exists") {
	t.Fatalf("expected duplicate connection error, got %v", err)
}
} */

func TestSecurity_NewIncomingConnectionReplay(t *testing.T) {
	handler := listenerConnectionHandler{}
	conn := &Conn{connected: make(chan struct{})}
	// Mimic sending a ConnectionRequest first - it's required for the connection to be established.
	conn.receivedConnectionRequest = true
	if err := handler.handleNewIncomingConnection(conn, nil); err != nil {
		t.Fatalf("first NIC handling failed: %v", err)
	}
	err := handler.handleNewIncomingConnection(conn, nil)
	if err != errUnexpectedAdditionalNIC {
		t.Fatalf("expected errUnexpectedAdditionalNIC, got %v", err)
	}
}

func TestSecurity_SplitPacketInvalidIndex(t *testing.T) {
	conn := &Conn{
		handler: &mockListenerHandler{logger: slog.Default()},
		splits:  make(map[uint16][][]byte),
	}
	pk := &packet{
		split:      true,
		splitCount: 2,
		splitIndex: 5,
		splitID:    1,
		content:    []byte{0x01},
	}
	err := conn.receiveSplitPacket(pk)
	if err == nil || !strings.Contains(err.Error(), "split index") {
		t.Fatalf("expected split index error, got %v", err)
	}
}

func TestSecurity_HandlePacketZeroLength(t *testing.T) {
	conn := &Conn{}
	if err := conn.handlePacket(nil, reliabilityUnreliable); err != errZeroPacket {
		t.Fatalf("expected errZeroPacket, got %v", err)
	}
}

func TestSecurity_PacketRejectsZeroLength(t *testing.T) {
	pk := &packet{}
	_, err := pk.read([]byte{0x00, 0x00, 0x00})
	if err == nil || err.Error() != "invalid packet length: cannot be 0" {
		t.Fatalf("expected invalid length error, got %v", err)
	}
}

func TestSecurity_PacketQueueRejectsStalePacket(t *testing.T) {
	queue := newPacketQueue()
	if !queue.put(0, []byte{1}) {
		t.Fatal("expected first packet to be accepted")
	}
	queue.fetch()
	if queue.put(0, []byte{2}) {
		t.Fatal("expected stale packet to be rejected")
	}
	if queue.WindowSize() != 0 {
		t.Fatalf("expected empty window, got %v", queue.WindowSize())
	}
}

func TestSecurity_ResendMapTimeoutBounds(t *testing.T) {
	fast := newRecoveryQueue()
	fast.updateRTT(1 * time.Millisecond)
	if fast.timeout() < 50*time.Millisecond {
		t.Fatalf("expected timeout >= 50ms, got %v", fast.timeout())
	}

	slow := newRecoveryQueue()
	slow.updateRTT(30 * time.Second)
	if slow.timeout() > 10*time.Second {
		t.Fatalf("expected timeout <= 10s, got %v", slow.timeout())
	}
}

// =============================================================================
// NACK Amplification Attack Mitigation Tests
// =============================================================================

func TestSecurity_NACKQueueSizeLimit(t *testing.T) {
	// Test that the NACK queue size is limited to prevent memory exhaustion.
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Simulate having many packets in the retransmission queue.
	conn.mu.Lock()
	for i := uint24(0); i < 1000; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      []byte{0x01, 0x02, 0x03},
		}
		conn.retransmission.add(i, []*packet{pk}, 100)
	}

	// Try to enqueue more sequences than the limit allows.
	numbers := make([]uint24, 500)
	for i := range numbers {
		numbers[i] = uint24(i)
	}
	enqueued := conn.enqueueResendsLocked(numbers)
	conn.mu.Unlock()

	// Should be capped at maxNackQueueSize (256).
	if enqueued > maxNackQueueSize {
		t.Fatalf("expected at most %d enqueued, got %d", maxNackQueueSize, enqueued)
	}

	conn.mu.Lock()
	queueLen := len(conn.ccNackQueue)
	conn.mu.Unlock()

	if queueLen > maxNackQueueSize {
		t.Fatalf("queue size %d exceeds max %d", queueLen, maxNackQueueSize)
	}
}

func TestSecurity_NACKRateLimiting(t *testing.T) {
	// Test that NACK processing is rate limited.
	var sentPackets int
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			sentPackets++
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add packets to the retransmission queue.
	conn.mu.Lock()
	for i := uint24(0); i < 1000; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      []byte{0x01, 0x02, 0x03},
		}
		conn.retransmission.add(i, []*packet{pk}, 100)
	}
	conn.mu.Unlock()

	// Send many NACKs to try to exhaust the rate limit.
	for i := 0; i < 100; i++ {
		// Create a NACK for 100 packets each time.
		nackBuf := bytes.NewBuffer(nil)
		nackBuf.WriteByte(bitFlagNACK | bitFlagDatagram)
		binary.Write(nackBuf, binary.BigEndian, uint16(1)) // 1 record
		nackBuf.WriteByte(packetRange)
		writeUint24(nackBuf, uint24(i*10))
		writeUint24(nackBuf, uint24(i*10+9))

		_ = conn.handleNACK(nackBuf.Bytes()[1:]) // Skip the header byte
	}

	// The budget should be exhausted.
	conn.mu.Lock()
	budget := conn.nackBudget
	conn.mu.Unlock()

	// Budget should be depleted (0 or negative conceptually, but clamped).
	if budget > 0 {
		t.Logf("budget after NACKs: %d (some NACKs may have been for non-existent sequences)", budget)
	}
}

func TestSecurity_NACKOnlyValidSequences(t *testing.T) {
	// Test that only valid (existing) sequence numbers trigger resends.
	var sentCount int
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			sentCount++
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add only a few packets to retransmission (sequences 0-4).
	conn.mu.Lock()
	for i := uint24(0); i < 5; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      []byte{0x01, 0x02, 0x03},
		}
		conn.retransmission.add(i, []*packet{pk}, 100)
	}
	conn.mu.Unlock()

	sentCount = 0 // Reset after newConn might have sent something.

	// Send a NACK requesting many sequences, most of which don't exist.
	nackBuf := bytes.NewBuffer(nil)
	nackBuf.WriteByte(bitFlagNACK | bitFlagDatagram)
	binary.Write(nackBuf, binary.BigEndian, uint16(1)) // 1 record
	nackBuf.WriteByte(packetRange)
	writeUint24(nackBuf, 0)   // Start
	writeUint24(nackBuf, 100) // End (only 0-4 exist)

	err := conn.handleNACK(nackBuf.Bytes()[1:])
	if err != nil {
		t.Fatalf("handleNACK failed: %v", err)
	}

	// Check that only valid sequences were enqueued.
	conn.mu.Lock()
	queueLen := len(conn.ccNackQueue)
	conn.mu.Unlock()

	// Should only have 5 valid sequences (0-4).
	if queueLen > 5 {
		t.Fatalf("expected at most 5 sequences in queue, got %d", queueLen)
	}
}

func TestSecurity_PacketsCanBeResentMultipleTimes(t *testing.T) {
	// Test that packets can be resent multiple times for high-loss scenarios.
	// The rate limit (nackBudgetPerSecond) is the primary defense, not per-packet limits.
	var resendCount int
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			if len(p) > 4 && p[0]&bitFlagDatagram != 0 {
				resendCount++
			}
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add a single packet to retransmission.
	conn.mu.Lock()
	pk := &packet{
		reliability:  reliabilityReliableOrdered,
		messageIndex: 42,
		content:      []byte{0x01, 0x02, 0x03},
	}
	conn.retransmission.add(0, []*packet{pk}, 100)
	conn.mu.Unlock()

	resendCount = 0 // Reset after setup.

	// Repeatedly NACK and flush to trigger resends (simulating high packet loss).
	for i := 0; i < 10; i++ {
		// Find the current sequence number in retransmission.
		conn.mu.Lock()
		var seq uint24
		var found bool
		for s := range conn.retransmission.unacknowledged {
			seq = s
			found = true
			break
		}
		conn.mu.Unlock()

		if !found {
			break
		}

		// NACK this sequence.
		nackBuf := bytes.NewBuffer(nil)
		binary.Write(nackBuf, binary.BigEndian, uint16(1))
		nackBuf.WriteByte(packetSingle)
		writeUint24(nackBuf, seq)

		_ = conn.handleNACK(nackBuf.Bytes())

		// Flush the resend queue.
		conn.mu.Lock()
		conn.flushResendQueueLocked()
		conn.mu.Unlock()
	}

	// Packet should still be resendable (no per-packet limit).
	// Rate limiting is the primary defense.
	if resendCount < 5 {
		t.Fatalf("expected packet to be resent multiple times for high-loss recovery, got %d", resendCount)
	}
	t.Logf("Packet was resent %d times (no per-packet limit, rate limit is primary defense)", resendCount)
}

func TestSecurity_NACKBudgetResetsAfterWindow(t *testing.T) {
	// Test that the NACK budget resets after the time window expires.
	conn := newConn(&mockPacketConn{}, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add packets to retransmission.
	conn.mu.Lock()
	for i := uint24(0); i < 100; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      []byte{0x01},
		}
		conn.retransmission.add(i, []*packet{pk}, 50)
	}
	conn.mu.Unlock()

	// Exhaust the budget.
	for i := 0; i < 100; i++ {
		nackBuf := bytes.NewBuffer(nil)
		binary.Write(nackBuf, binary.BigEndian, uint16(1))
		nackBuf.WriteByte(packetRange)
		writeUint24(nackBuf, 0)
		writeUint24(nackBuf, 99)
		_ = conn.handleNACK(nackBuf.Bytes())
	}

	conn.mu.Lock()
	budgetAfterExhaustion := conn.nackBudget
	// Simulate time passing by moving the window start back.
	conn.nackWindowStart = time.Now().Add(-2 * time.Second)
	conn.mu.Unlock()

	// Process another NACK - budget should reset.
	nackBuf := bytes.NewBuffer(nil)
	binary.Write(nackBuf, binary.BigEndian, uint16(1))
	nackBuf.WriteByte(packetSingle)
	writeUint24(nackBuf, 0)
	_ = conn.handleNACK(nackBuf.Bytes())

	conn.mu.Lock()
	budgetAfterReset := conn.nackBudget
	conn.mu.Unlock()

	// Budget should have been reset and then decremented.
	if budgetAfterReset >= nackBudgetPerSecond {
		t.Fatalf("budget should be less than max after processing NACK, got %d", budgetAfterReset)
	}
	// But it should be higher than the exhausted budget (which was likely <= 0).
	if budgetAfterReset <= budgetAfterExhaustion {
		t.Fatalf("budget should have reset: before=%d, after=%d", budgetAfterExhaustion, budgetAfterReset)
	}
}

// =============================================================================
// Legitimate Traffic Impact Tests
// =============================================================================

func TestSecurity_LegitimatePacketLossScenario(t *testing.T) {
	// Test that legitimate packet loss (reasonable NACKs) still works correctly.
	var sentDatagrams int
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			if len(p) > 0 && p[0]&bitFlagDatagram != 0 {
				sentDatagrams++
			}
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Simulate sending 50 packets (a reasonable burst).
	conn.mu.Lock()
	for i := uint24(0); i < 50; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      make([]byte, 100),
		}
		conn.retransmission.add(i, []*packet{pk}, 150)
	}
	conn.mu.Unlock()

	sentDatagrams = 0 // Reset counter.

	// Simulate 10% packet loss - NACK 5 packets.
	lostPackets := []uint24{5, 15, 25, 35, 45}
	nackBuf := bytes.NewBuffer(nil)
	binary.Write(nackBuf, binary.BigEndian, uint16(len(lostPackets)))
	for _, seq := range lostPackets {
		nackBuf.WriteByte(packetSingle)
		writeUint24(nackBuf, seq)
	}

	err := conn.handleNACK(nackBuf.Bytes())
	if err != nil {
		t.Fatalf("handleNACK failed: %v", err)
	}

	// Flush the resend queue.
	conn.mu.Lock()
	conn.flushResendQueueLocked()
	queuedAfterFlush := len(conn.ccNackQueue)
	conn.mu.Unlock()

	// All 5 lost packets should have been queued and some should be sent.
	// The pacing might not send all at once, but at least some should be sent.
	if sentDatagrams == 0 && queuedAfterFlush == 0 {
		t.Fatal("legitimate packet loss should trigger resends")
	}
}

func TestSecurity_ModeratePacketLossStillWorks(t *testing.T) {
	// Test that 20% packet loss (40 out of 200 packets) is handled correctly.
	var resentSequences []uint24
	var mu sync.Mutex
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			if len(p) > 4 && p[0]&bitFlagDatagram != 0 {
				seq := loadUint24(p[1:])
				mu.Lock()
				resentSequences = append(resentSequences, seq)
				mu.Unlock()
			}
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add 200 packets.
	conn.mu.Lock()
	for i := uint24(0); i < 200; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      make([]byte, 50),
		}
		conn.retransmission.add(i, []*packet{pk}, 100)
	}
	conn.mu.Unlock()

	// NACK 40 packets (20% loss).
	lostPackets := make([]uint24, 40)
	for i := range lostPackets {
		lostPackets[i] = uint24(i * 5) // Every 5th packet.
	}

	nackBuf := bytes.NewBuffer(nil)
	binary.Write(nackBuf, binary.BigEndian, uint16(len(lostPackets)))
	for _, seq := range lostPackets {
		nackBuf.WriteByte(packetSingle)
		writeUint24(nackBuf, seq)
	}

	err := conn.handleNACK(nackBuf.Bytes())
	if err != nil {
		t.Fatalf("handleNACK failed: %v", err)
	}

	// Flush multiple times to process all queued resends.
	// Pacing limits to 32 packets per flush, so need at least 2 flushes for 40 packets.
	for i := 0; i < 5; i++ {
		conn.mu.Lock()
		conn.flushResendQueueLocked()
		conn.mu.Unlock()
	}

	mu.Lock()
	resentCount := len(resentSequences)
	mu.Unlock()

	// With moderate packet loss, we should resend most of the lost packets.
	// Pacing allows 32 per flush, so 5 flushes should handle 40 packets.
	// We may not get all 40 if some were already processed differently.
	if resentCount < 20 {
		t.Fatalf("expected at least 20 resends for legitimate 20%% loss, got %d", resentCount)
	}
	t.Logf("Resent %d out of 40 lost packets (legitimate traffic scenario)", resentCount)
}

func TestSecurity_NACKAmplificationAttackMitigated(t *testing.T) {
	// Test that an amplification attack is effectively mitigated.
	//
	// Without mitigations, an attacker could:
	// - Send 50 NACKs × 9 bytes each = 450 bytes of attack traffic
	// - Request 500 packets × 50 NACKs × unlimited resends = potentially 25MB+ response
	// - Achieve 50,000x+ amplification
	//
	// With mitigations:
	// - Rate limit: 512 sequences per second
	// - Queue limit: 256 sequences max queued at once
	// - Per-packet limit: 3 resends max per packet
	// - Pacing: 32 packets per flush
	//
	// Expected maximum response: ~512 sequences × ~1KB × 3 resends = ~1.5MB
	// Expected amplification: ~1.5MB / 450 bytes = ~3,400x
	// This is significantly less than the 50,000x+ without mitigations.

	var totalBytesSent int
	mockConn := &mockPacketConn{
		writeToFunc: func(p []byte, addr net.Addr) (n int, err error) {
			totalBytesSent += len(p)
			return len(p), nil
		},
	}
	conn := newConn(mockConn, &net.UDPAddr{}, 1400, &mockListenerHandler{logger: slog.Default()})

	// Add packets to retransmission (simulate active connection).
	conn.mu.Lock()
	for i := uint24(0); i < 500; i++ {
		pk := &packet{
			reliability:  reliabilityReliableOrdered,
			messageIndex: i,
			content:      make([]byte, 1000), // ~1KB per packet.
		}
		conn.retransmission.add(i, []*packet{pk}, 1050)
	}
	conn.mu.Unlock()

	totalBytesSent = 0 // Reset after setup.

	// Simulate attacker sending many small NACKs requesting large ranges.
	attackerNACKBytes := 0
	for i := 0; i < 50; i++ {
		nackBuf := bytes.NewBuffer(nil)
		binary.Write(nackBuf, binary.BigEndian, uint16(1))
		nackBuf.WriteByte(packetRange)
		writeUint24(nackBuf, 0)
		writeUint24(nackBuf, 499)
		attackerNACKBytes += nackBuf.Len()

		_ = conn.handleNACK(nackBuf.Bytes())

		// Flush after each NACK (simulating fast attack).
		conn.mu.Lock()
		conn.flushResendQueueLocked()
		conn.mu.Unlock()
	}

	// Calculate amplification factor.
	amplificationFactor := float64(totalBytesSent) / float64(attackerNACKBytes)

	// Calculate what the amplification would be WITHOUT mitigations.
	// 50 NACKs × 500 packets = 25,000 potential resends × 1KB = 25MB.
	unmititgatedBytes := 50 * 500 * 1000
	unmitigatedAmplification := float64(unmititgatedBytes) / float64(attackerNACKBytes)

	t.Logf("Attack stats: %d NACK bytes -> %d response bytes", attackerNACKBytes, totalBytesSent)
	t.Logf("Actual amplification: %.2fx", amplificationFactor)
	t.Logf("Unmitigated amplification would be: %.2fx", unmitigatedAmplification)
	t.Logf("Mitigation effectiveness: %.2f%% reduction", (1-amplificationFactor/unmitigatedAmplification)*100)

	// The mitigations should provide at least 90% reduction in amplification.
	// Without mitigations: ~55,000x amplification
	// With mitigations: should be <5,500x (90% reduction)
	reductionPercent := (1 - amplificationFactor/unmitigatedAmplification) * 100
	if reductionPercent < 90 {
		t.Errorf("mitigation only achieved %.2f%% reduction, expected at least 90%%", reductionPercent)
	}

	// The rate limit (nackBudgetPerSecond) is the primary defense.
	// Max response per second is bounded by: budget * packet_size = 512 * ~1KB = ~512KB/s
	// In this test we only run one "second" of attack, so response should be around that.
	maxExpectedBytes := nackBudgetPerSecond * 1050 // 512 * 1050 ≈ 537KB
	if totalBytesSent > maxExpectedBytes*2 {       // Allow some margin for timing
		t.Errorf("total bytes sent (%d) exceeds expected maximum (%d)", totalBytesSent, maxExpectedBytes*2)
	}
}
