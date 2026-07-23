package raknet

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sandertv/go-raknet/congestion"
	"github.com/sandertv/go-raknet/message"
)

const (
	// protocolVersion is the current RakNet protocol version. This is Minecraft
	// specific.
	protocolVersion byte = 11

	minMTUSize    = 576
	maxMTUSize    = 1200
	maxWindowSize = 2048
)

// NACK amplification attack mitigations. These constants limit how aggressively
// we respond to NACK requests to prevent malicious clients from using NACKs to
// amplify traffic.
const (
	// maxNackQueueSize limits the number of sequence numbers that can be queued
	// for retransmission at any time. This prevents memory exhaustion from
	// excessive NACKs.
	maxNackQueueSize = 256
	// nackBudgetPerSecond limits the total number of NACKed sequence numbers
	// that will be processed per second per connection. This is the primary
	// defense against NACK amplification attacks - it bounds the maximum
	// resend rate regardless of how many NACKs an attacker sends.
	nackBudgetPerSecond = 512
)

// lossWindowBuckets is the number of 100ms buckets to form a 1s sliding window.
const lossWindowBuckets = 10

const connIncomingDatagramBuffer = 256

// Conn represents a connection to a specific client. It is not a real
// connection, as UDP is connectionless, but rather a connection emulated using
// RakNet. Methods may be called on Conn from multiple goroutines
// simultaneously.
type Conn struct {
	// rtt is the last measured round-trip time between both ends of the
	// connection. The rtt is measured in nanoseconds.
	rtt atomic.Int64

	closing atomic.Int64

	ctx        context.Context
	cancelFunc context.CancelFunc

	conn    net.PacketConn
	raddr   net.Addr
	handler connectionHandler

	once      sync.Once
	accepted  atomic.Bool
	connected chan struct{}
	incoming  chan []byte

	ticker chan time.Time

	mu  sync.Mutex
	buf *bytes.Buffer

	ackBuf, nackBuf *bytes.Buffer

	pk *packet

	seq, orderIndex, messageIndex, sequenceIndex uint24
	splitID                                      uint32

	// mtu is the MTU size of the connection. Packets longer than this size
	// must be split into fragments for them to arrive at the client without
	// losing bytes.
	mtu uint16

	acksLeft int

	// splits is a map of slices indexed by split IDs. The length of each of the
	// slices is equal to the split count, and packets are positioned in that
	// slice indexed by the split index.
	splits map[uint16][][]byte

	// acknowledgements ...
	acknowledgements map[uint24]*fullPacketAcknowledgement
	// oldACKSequences is a map of sequence numbers that have been acknowledged.
	oldACKSequences map[uint24]*fullPacketAcknowledgement
	// onACK ...
	onACK func(ackID uint64)

	// win is an ordered queue used to track which datagrams were received and
	// which datagrams were missing, so that we can send NACKs to request
	// missing datagrams.
	win *datagramWindow

	// ackSlice is a slice containing sequence numbers of datagrams that were
	// received over the last second. When ticked, all of these packets are sent
	// in an ACK and the slice is cleared.
	ackSlice []uint24
	ackMu    sync.Mutex

	// packetQueue is an ordered queue containing packets indexed by their order
	// index.
	packetQueue *packetQueue
	// receivedMessageIndices tracks message indices that have been received for
	// reliable packets to prevent duplicate handling.
	receivedMessageIndices *datagramWindow
	// highestUnreliableSeqIndex tracks the highest sequence index received for
	// unreliable sequenced packets, used to drop out-of-order packets.
	highestUnreliableSeqIndex uint24
	// highestReliableSeqIndex tracks the highest sequence index received for
	// reliable sequenced packets, used to drop out-of-order packets.
	highestReliableSeqIndex uint24
	// packets is a channel containing content of packets that were fully
	// processed. Calling Conn.Read() consumes a value from this channel.
	packets chan []byte

	// retransmission is a queue filled with packets that were sent with a given
	// datagram sequence number.
	retransmission *resendMap

	lastActivity atomic.Int64
	rawLatency   atomic.Int64
	createdAt    time.Time

	// --- Congestion control state (datagram-based AIMD) ---
	// ccPending holds packets waiting to be assigned a datagram sequence and sent when cwnd allows.
	ccPending []*packet
	// ccNackQueue holds sequence numbers that should be retransmitted due to NACK/timeout, paced over time.
	ccNackQueue []uint24
	// ccNackSet is a de-duplication set for sequence numbers in ccNackQueue.
	ccNackSet map[uint24]struct{}

	// cc is the congestion controller (UDT or SlidingWindow).
	cc congestion.Controller
	// sendBudget is the number of bytes we are allowed to send this tick (post-slow-start).
	sendBudget int
	// resendBudget is the number of bytes we are allowed to spend on retransmissions this tick.
	resendBudget int
	// lastTickTime is the time of the previous tick, for budget refill.
	lastTickTime time.Time
	// ccTotalAckedBytes tracks the cumulative user-data bytes ACKed, used for slow start CWND.
	ccTotalAckedBytes uint64

	// --- NACK amplification attack mitigation state ---
	// nackBudget is the remaining number of NACKed sequences allowed this window.
	nackBudget int
	// nackWindowStart marks the beginning of the current rate limit window.
	nackWindowStart time.Time

	// --- Sliding window packet loss accounting (1s window, 10x100ms buckets) ---
	lossMetricsMu       sync.Mutex
	lossMetricsBucket   int
	lossOutTotalBuckets [lossWindowBuckets]uint32
	lossOutLostBuckets  [lossWindowBuckets]uint32
	lossInTotalBuckets  [lossWindowBuckets]uint32
	lossInLostBuckets   [lossWindowBuckets]uint32
	// Recent lost sequence numbers (dedup within ~1s window).
	lostOutRecent map[uint24]int64 // unix nano timestamp of when counted
	lostInRecent  map[uint24]int64 // unix nano timestamp of when counted

	// receivedConnectionRequest is a boolean indicating if the remote connection sent a ConnectionRequest packet.
	receivedConnectionRequest bool

	incomingOnce       sync.Once
	incomingErrHandler func(error)
}

// newConn constructs a new connection specifically dedicated to the address
// passed.
func newConn(conn net.PacketConn, raddr net.Addr, mtu uint16, h connectionHandler) *Conn {
	mtu = min(max(mtu, minMTUSize), maxMTUSize)
	c := &Conn{
		raddr:   raddr,
		conn:    conn,
		mtu:     mtu,
		handler: h,

		pk:        new(packet),
		connected: make(chan struct{}),
		packets:   make(chan []byte, 4096),

		splits:           make(map[uint16][][]byte),
		acknowledgements: make(map[uint24]*fullPacketAcknowledgement),
		oldACKSequences:  make(map[uint24]*fullPacketAcknowledgement),

		win:                    newDatagramWindow(),
		packetQueue:            newPacketQueue(),
		receivedMessageIndices: newDatagramWindow(),
		retransmission:         newRecoveryQueue(),

		buf:     bytes.NewBuffer(make([]byte, 0, mtu-28)), // - headers.
		ackBuf:  bytes.NewBuffer(make([]byte, 0, 128)),
		nackBuf: bytes.NewBuffer(make([]byte, 0, 64)),

		createdAt: time.Now(),
	}

	c.ctx, c.cancelFunc = context.WithCancel(context.Background())
	//c.cc = congestion.NewSlidingWindow(int(mtu))
	c.cc = congestion.NewUDT(int(mtu))
	c.ccPending = nil
	c.ccNackQueue = nil
	c.ccNackSet = make(map[uint24]struct{})
	c.sendBudget = c.cc.GetTransmissionBandwidth(0, 0, false)
	c.resendBudget = c.cc.GetRetransmissionBandwidth(0, 0, false)
	// Initialize NACK amplification mitigations.
	c.nackBudget = nackBudgetPerSecond
	c.nackWindowStart = time.Now()
	c.lostOutRecent = make(map[uint24]int64)
	c.lostInRecent = make(map[uint24]int64)
	t := time.Now()
	c.lastActivity.Store(t.UnixMilli())
	c.lastTickTime = t
	// Buffered channel to receive ticks from the shared global ticker.
	c.ticker = make(chan time.Time, 1)
	registerConnection(c)
	go c.startTicking()
	return c
}

// effectiveMTU returns the mtu size without the space allocated for IP and
// UDP headers (28 bytes).
func (conn *Conn) effectiveMTU() uint16 {
	return conn.mtu - 28
}

// isNewerSequenceIndex returns true if 'incoming' is newer than 'current',
// handling uint24 wraparound by treating the sequence space as circular.
// A sequence is considered "newer" if it's within the forward half of the
// sequence space from the current position.
func (conn *Conn) isNewerSequenceIndex(incoming, current uint24) bool {
	if incoming == current {
		return false
	}
	// Use the "half-space" algorithm: if the difference (when treating
	// as unsigned) is less than half the sequence space, incoming > current
	// means it's newer. If incoming < current but the backward distance
	// is more than half the space, it wrapped around and is newer.
	const halfSpace uint24 = 0x800000 // Half of 0xFFFFFF + 1
	diff := incoming - current
	return diff < halfSpace
}

// startTicking makes the connection start ticking, sending ACKs and pings to
// the other end where necessary and checking if the connection should be timed
// out. It receives ticks from the shared global 10ms ticker.
func (conn *Conn) startTicking() {
	var currentTick int64
	for {
		select {
		case t := <-conn.ticker:
			currentTick++
			conn.tick(currentTick, t)
		case <-conn.ctx.Done():
			return
		}
	}
}

func (conn *Conn) tick(currentTick int64, t time.Time) {
	// Flush accumulated acknowledgements every 100ms.
	if currentTick%10 == 0 {
		conn.flushACKs()
	}

	conn.mu.Lock()
	// Update transmission budget from UDT controller.
	dt := t.Sub(conn.lastTickTime)
	conn.lastTickTime = t
	unacked := conn.retransmission.inFlightBytesEstimate()
	isContinuous := len(conn.ccPending) > 0
	conn.sendBudget = conn.cc.GetTransmissionBandwidth(dt, unacked, isContinuous)
	conn.resendBudget = conn.cc.GetRetransmissionBandwidth(dt, unacked, isContinuous)
	conn.flushSendQueueLocked()
	conn.flushResendQueueLocked()
	conn.mu.Unlock()

	// Rotate the metrics bucket every 100ms.
	if currentTick%10 == 0 {
		conn.lossMetricsMu.Lock()
		conn.lossMetricsBucket = (conn.lossMetricsBucket + 1) % lossWindowBuckets
		conn.lossOutTotalBuckets[conn.lossMetricsBucket] = 0
		conn.lossOutLostBuckets[conn.lossMetricsBucket] = 0
		conn.lossInTotalBuckets[conn.lossMetricsBucket] = 0
		conn.lossInLostBuckets[conn.lossMetricsBucket] = 0
		// Prune dedup maps for entries older than 1s.
		nowNano := time.Now().UnixNano()
		cutoff := nowNano - int64(time.Second)
		for k, ts := range conn.lostOutRecent {
			if ts < cutoff {
				delete(conn.lostOutRecent, k)
			}
		}
		for k, ts := range conn.lostInRecent {
			if ts < cutoff {
				delete(conn.lostInRecent, k)
			}
		}
		conn.lossMetricsMu.Unlock()
	}

	// Every 300ms: check if we need to resend any packets.
	if currentTick%30 == 0 {
		conn.checkResend(t)
	}

	if unix := conn.closing.Load(); unix != 0 {
		before := conn.acksLeft
		conn.mu.Lock()
		conn.acksLeft = len(conn.retransmission.unacknowledged)
		conn.mu.Unlock()

		if before != 0 && conn.acksLeft == 0 {
			conn.closeImmediately()
		}
		since := t.Sub(time.Unix(unix, 0))
		if (conn.acksLeft == 0 && since > time.Second) || since > time.Second*5 {
			conn.closeImmediately()
		}
	}

	if currentTick%50 == 0 {
		// No activity for too long (15 seconds): close the connection.
		if t.UnixMilli()-conn.lastActivity.Load() > 15_000 {
			conn.closeImmediately()
			return
		}

		// Ping the other end periodically to prevent timeouts.
		_ = conn.sendWithReliability(&message.ConnectedPing{PingTime: timestamp()}, reliabilityUnreliable)
	}

}

// flushACKs flushes all pending datagram acknowledgements.
func (conn *Conn) flushACKs() {
	conn.ackMu.Lock()
	defer conn.ackMu.Unlock()

	if len(conn.ackSlice) > 0 {
		// Write an ACK packet to the connection containing all datagram
		// sequence numbers that we received since the last tick.
		if err := conn.sendACK(conn.ackSlice...); err != nil {
			return
		}
		conn.ackSlice = conn.ackSlice[:0]
		// Reset the oldest unacknowledged ACK timestamp after sending.
		conn.cc.OnSendACK()
	}
}

// checkResend checks if the connection needs to resend any packets. It sends
// an ACK for packets it has received and sends any packets that have been
// pending for too long.
func (conn *Conn) checkResend(now time.Time) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	var (
		resend []uint24
		// Use the smoothed RTT/RTO from the resendMap for more accurate timeouts.
		rtt = conn.retransmission.rtt()
		rto = conn.retransmission.timeout()
	)
	conn.rtt.Store(int64(rtt))

	for seq, t := range conn.retransmission.unacknowledged {
		// These packets have not been acknowledged for too long: We resend them
		// by ourselves, even though no NACK has been issued yet.
		if now.Sub(t.timestamp) > rto {
			resend = append(resend, seq)
		}
	}
	if len(resend) > 0 {
		// Timeout-based loss detection.
		conn.cc.OnResend()
		// Count outbound loss events detected via timeout (deduplicated).
		conn.metricsMarkOutLostSeqs(resend)
	}
	conn.enqueueResendsLocked(resend)
}

func (conn *Conn) OnACK(f func(ackID uint64)) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.onACK = f
}

// Write writes a buffer b over the RakNet connection. The amount of bytes
// written n is always equal to the length of the bytes written if writing was
// successful. If not, an error is returned and n is 0. Write may be called
// simultaneously from multiple goroutines, but will write one by one.
func (conn *Conn) Write(b []byte) (n int, err error) {
	if conn.ctx == nil {
		return 0, errors.New("connection not initialized properly")
	}

	select {
	case <-conn.ctx.Done():
		return 0, conn.error(net.ErrClosed, "write")
	default:
		conn.mu.Lock()
		defer conn.mu.Unlock()
		n, err = conn.write(b)
		return n, conn.error(err, "write")
	}
}

func (conn *Conn) WriteWithACK(b []byte, ackID uint64) (n int, err error) {
	select {
	case <-conn.ctx.Done():
		return 0, conn.error(net.ErrClosed, "write")
	default:
		conn.mu.Lock()
		defer conn.mu.Unlock()
		n, err = conn.writeWithACK(b, ackID)
		return n, conn.error(err, "write")
	}
}

func (conn *Conn) writeWithACK(b []byte, ackID uint64) (n int, err error) {
	fragments := split(b, conn.effectiveMTU())
	orderIndex := conn.orderIndex.Inc()
	splitID := uint16(conn.splitID)
	if len(fragments) > 1 {
		conn.splitID++
	}
	// Register an acknowledgement group for this write, keyed by orderIndex,
	// expecting all fragments to be acknowledged.
	if conn.onACK != nil {
		conn.acknowledgements[orderIndex] = &fullPacketAcknowledgement{remaining: uint32(len(fragments)), internalID: ackID}
	}
	for splitIndex, content := range fragments {
		pk := newPacket(reliabilityReliableOrdered)
		if cap(pk.content) < len(content) {
			pk.content = make([]byte, len(content))
		}
		// We set the actual slice size to the same size as the content. It
		// might be bigger than the previous size, in which case it will grow,
		// which is fine as the underlying array will always be big enough.
		pk.content = pk.content[:len(content)]
		copy(pk.content, content)

		pk.orderIndex = orderIndex
		pk.messageIndex = conn.messageIndex.Inc()
		if pk.split = len(fragments) > 1; pk.split {
			// If there were more than one fragment, the pk was split, so we
			// need to make sure we set the appropriate fields.
			pk.splitCount = uint32(len(fragments))
			pk.splitIndex = uint32(splitIndex)
			pk.splitID = splitID
		}
		// Queue or send depending on congestion window
		if err = conn.queueOrSend(pk); err != nil {
			return 0, err
		}
		n += len(content)
	}
	return n, nil
}

// WriteWithReliability writes a buffer b over the RakNet connection using the
// specified reliability layer. The amount of bytes written n is always equal to
// the length of the bytes written if writing was successful. If not, an error
// is returned and n is 0. WriteWithReliability may be called simultaneously
// from multiple goroutines, but will write one by one.
//
// Available reliability constants:
//   - ReliabilityUnreliable: Packet may arrive out of order, be duplicated, or not arrive.
//   - ReliabilityUnreliableSequenced: Packet may not arrive, but will be in order if it does.
//   - ReliabilityReliable: Packet will arrive, but may be out of order.
//   - ReliabilityReliableOrdered: Packet will arrive in order (default for Write).
//   - ReliabilityReliableSequenced: Packet will arrive in order, dropping older sequenced packets.
func (conn *Conn) WriteWithReliability(b []byte, reliability byte) (n int, err error) {
	select {
	case <-conn.ctx.Done():
		return 0, conn.error(net.ErrClosed, "write")
	default:
		conn.mu.Lock()
		defer conn.mu.Unlock()
		n, err = conn.writeWithReliability(b, reliability)
		return n, conn.error(err, "write")
	}
}

// ErrUnreliableSplitNotSupported is returned when attempting to send an
// unreliable packet that exceeds the MTU size. Unreliable packets cannot be
// split because lost fragments cannot be retransmitted.
var ErrUnreliableSplitNotSupported = errors.New("unreliable packets cannot be split")

// writeWithReliability writes a buffer b over the RakNet connection using the
// specified reliability layer. Unlike WriteWithReliability, this function will
// not lock.
func (conn *Conn) writeWithReliability(b []byte, reliability byte) (n int, err error) {
	// Determine if this is an unreliable packet (should not be queued or
	// added to retransmission).
	isUnreliable := reliability == reliabilityUnreliable ||
		reliability == reliabilityUnreliableSequenced
	if isUnreliable && len(b) > int(conn.effectiveMTU()) {
		return 0, ErrUnreliableSplitNotSupported
	}

	fragments := split(b, conn.effectiveMTU())
	splitID := uint16(conn.splitID)
	if len(fragments) > 1 {
		conn.splitID++
	}

	// Only increment order/sequence indices if the reliability requires them.
	var orderIndex, sequenceIndex uint24
	needsOrder := reliability == reliabilityUnreliableSequenced ||
		reliability == reliabilityReliableOrdered ||
		reliability == reliabilityReliableSequenced
	needsSequence := reliability == reliabilityUnreliableSequenced ||
		reliability == reliabilityReliableSequenced

	if needsOrder {
		orderIndex = conn.orderIndex.Inc()
	}
	if needsSequence {
		sequenceIndex = conn.sequenceIndex.Inc()
	}

	for splitIndex, content := range fragments {
		pk := newPacket(reliability)
		if cap(pk.content) < len(content) {
			pk.content = make([]byte, len(content))
		}
		pk.content = pk.content[:len(content)]
		copy(pk.content, content)

		// Set indices based on reliability type.
		if pk.reliable() {
			pk.messageIndex = conn.messageIndex.Inc()
		}
		if needsSequence {
			pk.sequenceIndex = sequenceIndex
		}
		if needsOrder {
			pk.orderIndex = orderIndex
		}

		if pk.split = len(fragments) > 1; pk.split {
			pk.splitCount = uint32(len(fragments))
			pk.splitIndex = uint32(splitIndex)
			pk.splitID = splitID
		}

		if isUnreliable {
			// Unreliable packets are sent immediately without congestion
			// control queuing and are not tracked for retransmission.
			if err = conn.sendUnreliableDatagram([]*packet{pk}); err != nil {
				return 0, err
			}
		} else {
			if err = conn.queueOrSend(pk); err != nil {
				return 0, err
			}
		}
		n += len(content)
	}
	return n, nil
}

// write writes a buffer b over the RakNet connection. The amount of bytes
// written n is always equal to the length of the bytes written if the write
// was successful. If not, an error is returned and n is 0. Write may be called
// simultaneously from multiple goroutines, but will write one by one. Unlike
// Write, write will not lock.
func (conn *Conn) write(b []byte) (n int, err error) {
	fragments := split(b, conn.effectiveMTU())
	orderIndex := conn.orderIndex.Inc()
	splitID := uint16(conn.splitID)
	if len(fragments) > 1 {
		conn.splitID++
	}
	for splitIndex, content := range fragments {
		pk := newPacket(reliabilityReliableOrdered)
		if cap(pk.content) < len(content) {
			pk.content = make([]byte, len(content))
		}
		// We set the actual slice size to the same size as the content. It
		// might be bigger than the previous size, in which case it will grow,
		// which is fine as the underlying array will always be big enough.
		pk.content = pk.content[:len(content)]
		copy(pk.content, content)

		pk.orderIndex = orderIndex
		pk.messageIndex = conn.messageIndex.Inc()
		if pk.split = len(fragments) > 1; pk.split {
			// If there were more than one fragment, the pk was split, so we
			// need to make sure we set the appropriate fields.
			pk.splitCount = uint32(len(fragments))
			pk.splitIndex = uint32(splitIndex)
			pk.splitID = splitID
		}
		// Queue or send depending on congestion window
		if err = conn.queueOrSend(pk); err != nil {
			return 0, err
		}
		n += len(content)
	}
	return n, nil
}

// Read reads from the connection into the byte slice passed. If successful,
// the amount of bytes read n is returned, and the error returned will be nil.
// Read blocks until a packet is received over the connection, or until the
// session is closed or the read times out, in which case an error is returned.
func (conn *Conn) Read(b []byte) (n int, err error) {
	select {
	case <-conn.ctx.Done():
		return 0, conn.error(net.ErrClosed, "read")
	case pk, ok := <-conn.packets:
		if !ok {
			return 0, conn.error(net.ErrClosed, "read")
		} else if len(b) < len(pk) {
			return 0, conn.error(ErrBufferTooSmall, "read")
		}
		return copy(b, pk), nil
	}
}

// ReadPacket attempts to read the next packet as a byte slice. ReadPacket
// blocks until a packet is received over the connection, or until the session
// is closed or the read times out, in which case an error is returned.
func (conn *Conn) ReadPacket() (b []byte, err error) {
	select {
	case <-conn.ctx.Done():
		return nil, conn.error(net.ErrClosed, "read")
	case pk, ok := <-conn.packets:
		if !ok {
			return nil, conn.error(net.ErrClosed, "read")
		}
		return pk, nil
	}
}

// Close closes the connection. All blocking Read or Write actions are
// cancelled and will return an error, as soon as the closing of the connection
// is acknowledged by the client.
func (conn *Conn) Close() error {
	conn.closing.CompareAndSwap(0, time.Now().Unix())
	return nil
}

func (conn *Conn) setIncomingDatagramErrorHandler(f func(error)) {
	conn.incomingErrHandler = f
}

var drops int

func (conn *Conn) queueIncomingDatagram(payload []byte) {
	conn.incomingOnce.Do(func() {
		conn.incoming = make(chan []byte, connIncomingDatagramBuffer)
		go conn.runIncomingDatagramLoop()
	})

	select {
	case <-conn.ctx.Done():
		return
	case conn.incoming <- payload:
	default:
		// Avoid stalling the listener read loop when a single connection falls
		// behind; dropped datagrams are naturally recovered via RakNet NACKs.
	}
}

func (conn *Conn) runIncomingDatagramLoop() {
	for {
		select {
		case <-conn.ctx.Done():
			return
		case payload := <-conn.incoming:
			if err := conn.receive(payload); err != nil {
				conn.closeImmediately()
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				if conn.incomingErrHandler != nil {
					conn.incomingErrHandler(err)
				}
			}
		}
	}
}

// Context returns the connection's context. The context is canceled when
// the connection is closed, allowing for cancellation of operations
// that are tied to the lifecycle of the connection.
func (conn *Conn) Context() context.Context {
	return conn.ctx
}

// closeImmediately sends a Disconnect notification to the other end of the
// connection and closes the underlying UDP connection immediately.
func (conn *Conn) closeImmediately() {
	conn.once.Do(func() {
		_, _ = conn.Write([]byte{message.IDDisconnectNotification})
		conn.handler.close(conn)
		unregisterTickedConnection(conn)
		conn.cancelFunc()

		if f := filter; f != nil {
			_ = f.UnregisterConnection(resolve(conn.raddr))
		}

		conn.mu.Lock()
		defer conn.mu.Unlock()

		// Make sure to return all unacknowledged packets to the packet pool.
		for _, record := range conn.retransmission.unacknowledged {
			for _, pk := range record.packets {
				returnPacket(pk)
			}
		}
		clear(conn.retransmission.unacknowledged)
	})
}

// closeImmediateSilent internally closes the connection without sending a disconnect notification to the remote end.
func (conn *Conn) closeImmediateSilent() {
	conn.once.Do(func() {
		conn.handler.close(conn)
		unregisterTickedConnection(conn)
		conn.cancelFunc()

		if f := filter; f != nil {
			_ = f.UnregisterConnection(resolve(conn.raddr))
		}

		conn.mu.Lock()
		defer conn.mu.Unlock()
		// Make sure to return all unacknowledged packets to the packet pool.
		for _, record := range conn.retransmission.unacknowledged {
			for _, pk := range record.packets {
				returnPacket(pk)
			}
		}
		clear(conn.retransmission.unacknowledged)
	})
}

// RemoteAddr returns the remote address of the connection, meaning the address
// this connection leads to.
func (conn *Conn) RemoteAddr() net.Addr {
	return conn.raddr
}

// LocalAddr returns the local address of the connection, which is always the
// same as the listener's.
func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

// OutboundLossRatio returns the percentage of outbound datagrams lost within
// the last 1 second sliding window. If no datagrams were sent in that window,
// it returns 0.
func (conn *Conn) OutboundLossRatio() float64 {
	conn.lossMetricsMu.Lock()
	defer conn.lossMetricsMu.Unlock()
	var total, lost uint64
	for i := 0; i < lossWindowBuckets; i++ {
		total += uint64(conn.lossOutTotalBuckets[i])
		lost += uint64(conn.lossOutLostBuckets[i])
	}
	den := total + lost
	if den == 0 {
		return 0
	}
	return float64(lost) / float64(den) * 100.0
}

// InboundLossRatio returns the percentage of inbound datagrams lost (as
// detected via missing indices/NACKs) within the last 1 second sliding window.
// If no datagrams were received/expected in that window, it returns 0.
func (conn *Conn) InboundLossRatio() float64 {
	conn.lossMetricsMu.Lock()
	defer conn.lossMetricsMu.Unlock()
	var total, lost uint64
	for i := 0; i < lossWindowBuckets; i++ {
		total += uint64(conn.lossInTotalBuckets[i])
		lost += uint64(conn.lossInLostBuckets[i])
	}
	den := total + lost
	if den == 0 {
		return 0
	}
	return float64(lost) / float64(den) * 100.0
}

// SetReadDeadline is unimplemented. It always returns ErrNotSupported.
func (conn *Conn) SetReadDeadline(time.Time) error { return ErrNotSupported }

// SetWriteDeadline is unimplemented. It always returns ErrNotSupported.
func (conn *Conn) SetWriteDeadline(time.Time) error { return ErrNotSupported }

// SetDeadline is unimplemented. It always returns ErrNotSupported.
func (conn *Conn) SetDeadline(time.Time) error { return ErrNotSupported }

// Latency returns the raw latency of the connection in milliseconds measured by the response times to ConnectedPing packets.
func (conn *Conn) Latency() time.Duration {
	//return time.Duration(conn.rtt.Load() / 2)
	return time.Duration(conn.rawLatency.Load()) * time.Millisecond
}

// send encodes an encoding.BinaryMarshaler and writes it to the Conn.
func (conn *Conn) send(pk encoding.BinaryMarshaler) error {
	b, _ := pk.MarshalBinary()
	_, err := conn.Write(b)
	return err
}

// sendWithReliability encodes an encoding.BinaryMarshaler and writes it to the Conn with the specified reliability.
func (conn *Conn) sendWithReliability(pk encoding.BinaryMarshaler, reliability byte) error {
	b, _ := pk.MarshalBinary()
	_, err := conn.WriteWithReliability(b, reliability)
	return err
}

var (
	// packetPool is used to pool packets that encapsulate their content.
	packetPool = sync.Pool{New: func() any { return &packet{} }}
)

func newPacket(reliability byte) *packet {
	pk := packetPool.Get().(*packet)
	pk.reliability = reliability
	pk.messageIndex = 0
	pk.sequenceIndex = 0
	pk.orderIndex = 0
	pk.split = false
	pk.splitCount = 0
	pk.splitID = 0
	pk.splitIndex = 0
	if len(pk.content) != 0 {
		pk.content = pk.content[:0]
	}
	return pk
}

func returnPacket(pk *packet) {
	pk.messageIndex = 0
	pk.sequenceIndex = 0
	pk.orderIndex = 0
	pk.split = false
	pk.splitCount = 0
	pk.splitID = 0
	pk.splitIndex = 0
	if len(pk.content) != 0 {
		pk.content = pk.content[:0]
	}
	packetPool.Put(pk)
}

// receive receives a packet from the connection, handling it as appropriate.
// If not successful, an error is returned.
func (conn *Conn) receive(b []byte) error {
	conn.lastActivity.Store(time.Now().UnixMilli())
	switch {
	case b[0]&bitFlagACK != 0:
		return conn.handleACK(b[1:])
	case b[0]&bitFlagNACK != 0:
		return conn.handleNACK(b[1:])
	case b[0]&bitFlagDatagram != 0:
		return conn.receiveDatagram(b[1:])
	}
	return nil
}

// receiveDatagram handles the receiving of a datagram found in buffer b. If
// successful, all packets inside the datagram are handled. if not, an error is
// returned.
func (conn *Conn) receiveDatagram(b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("read datagram: %w", io.ErrUnexpectedEOF)
	}
	seq := loadUint24(b)
	if !conn.win.add(seq) {
		// Datagram was already received, this might happen if a packet took a
		// long time to arrive, and we already sent a NACK for it. This is
		// expected to happen sometimes under normal circumstances, so no reason
		// to return an error.
		return nil
	}

	if conn.win.shift() == 0 {
		// Datagram window couldn't be shifted up, so we're still missing
		// packets.
		rtt := time.Duration(conn.rtt.Load())
		if missing := conn.win.missing(rtt + rtt/2); len(missing) > 0 {
			// Count inbound missing datagrams (loss events) within the window (deduplicated).
			conn.metricsMarkInLostSeqs(missing)
			if err := conn.sendNACK(missing); err != nil {
				return fmt.Errorf("receive datagram: send NACK: %w", err)
			}
		}
	}
	if conn.win.size() > maxWindowSize && conn.handler.limitsEnabled() {
		return fmt.Errorf("receive datagram: queue window size is too big (%v-%v)", conn.win.lowest, conn.win.highest)
	}
	return conn.handleDatagram(b[3:], seq)
}

// handleDatagram handles the contents of a datagram encoded in a bytes.Buffer.
func (conn *Conn) handleDatagram(b []byte, seq uint24) error {
	for len(b) > 0 {
		n, err := conn.pk.read(b)
		if err != nil {
			return fmt.Errorf("handle datagram: read packet: %w", err)
		}
		b = b[n:]

		handle := conn.receivePacket
		if conn.pk.split {
			handle = conn.receiveSplitPacket
		}
		if err := handle(conn.pk); err != nil {
			return fmt.Errorf("handle datagram: receive packet: %w", err)
		}
	}

	conn.metricsIncInTotal(1)
	conn.ackMu.Lock()
	conn.ackSlice = append(conn.ackSlice, seq)
	// Track when the first ACK was queued for shouldSendACKs timing.
	conn.cc.OnQueueACK(timestamp())
	conn.ackMu.Unlock()

	return nil
}

// receivePacket handles the receiving of a packet. It puts the packet in the
// queue and takes out all packets that were obtainable after that, and handles
// them.
func (conn *Conn) receivePacket(packet *packet) error {
	switch packet.reliability {
	case reliabilityUnreliable:
		// Unreliable packets are handled immediately without any guarantees.
		return conn.handlePacket(packet.content, packet.reliability)

	case reliabilityReliable:
		// Reliable packets use messageIndex to prevent duplicates.
		// If we've already seen this messageIndex, drop the packet.
		if !conn.receivedMessageIndices.add(packet.messageIndex) {
			return nil
		}
		conn.receivedMessageIndices.shift()
		return conn.handlePacket(packet.content, packet.reliability)

	case reliabilityUnreliableSequenced:
		// Sequenced packets should be dropped if they arrive out of order
		// (i.e., if their sequence index is older than the highest we've seen).
		if packet.sequenceIndex != conn.highestUnreliableSeqIndex &&
			!conn.isNewerSequenceIndex(packet.sequenceIndex, conn.highestUnreliableSeqIndex) {
			return nil
		}
		conn.highestUnreliableSeqIndex = packet.sequenceIndex + 1
		return conn.handlePacket(packet.content, packet.reliability)

	case reliabilityReliableSequenced:
		// Reliable sequenced packets use messageIndex to prevent duplicates
		// and sequenceIndex to drop out-of-order packets.
		if !conn.receivedMessageIndices.add(packet.messageIndex) {
			// Already received this message, drop the duplicate.
			return nil
		}
		conn.receivedMessageIndices.shift()
		// Sequenced packets should be dropped if they arrive out of order
		// (i.e., if their sequence index is older than the highest we've seen).
		if packet.sequenceIndex != conn.highestReliableSeqIndex &&
			!conn.isNewerSequenceIndex(packet.sequenceIndex, conn.highestReliableSeqIndex) {
			return nil
		}
		conn.highestReliableSeqIndex = packet.sequenceIndex + 1
		return conn.handlePacket(packet.content, packet.reliability)

	case reliabilityReliableOrdered:
		// Reliable ordered packets must be delivered in order.
		if !conn.packetQueue.put(packet.orderIndex, packet.content) {
			// An ordered packet arrived twice.
			return nil
		}
		if conn.packetQueue.WindowSize() > maxWindowSize && conn.handler.limitsEnabled() {
			return fmt.Errorf("packet queue window size is too big (%v-%v)", conn.packetQueue.lowest, conn.packetQueue.highest)
		}
		for _, content := range conn.packetQueue.fetch() {
			if err := conn.handlePacket(content, reliabilityReliableOrdered); err != nil {
				return err
			}
		}
		return nil

	default:
		// Unknown reliability type, handle immediately as a fallback.
		return conn.handlePacket(packet.content, packet.reliability)
	}
}

var errZeroPacket = errors.New("handle packet: zero packet length")

// handlePacket handles a packet serialised in byte slice b. If not successful,
// an error is returned. If the packet was not handled by RakNet, it is sent to
// the packet channel.
func (conn *Conn) handlePacket(b []byte, reliability byte) error {
	if len(b) == 0 {
		return errZeroPacket
	}
	if conn.closing.Load() != 0 {
		// Don't continue handling packets if the connection is being closed.
		return nil
	}
	handled, err := conn.handler.handle(conn, b, reliability)
	if err != nil {
		return fmt.Errorf("handle packet: %w", err)
	}
	if !handled {
		// Respect connection cancellation so senders do not block forever after
		// closeImmediately cancels the context (Read/ReadPacket do the same).
		select {
		case <-conn.ctx.Done():
			return nil
		case conn.packets <- b:
		}
	}
	return nil
}

func resolve(addr net.Addr) netip.AddrPort {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		uaddr := *udpAddr
		ip, _ := netip.AddrFromSlice(uaddr.IP)
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		return netip.AddrPortFrom(ip, uint16(uaddr.Port))
	}
	return netip.AddrPort{}
}

// receiveSplitPacket handles a passed split packet. If it is the last split
// packet of its sequence, it will continue handling the full packet as it
// otherwise would. An error is returned if the packet was not valid.
func (conn *Conn) receiveSplitPacket(p *packet) error {
	const maxSplitCount = 512
	const maxConcurrentSplits = 16

	if p.splitCount > maxSplitCount && conn.handler.limitsEnabled() {
		return fmt.Errorf("split packet: split count %v exceeds the maximum %v", p.splitCount, maxSplitCount)
	}
	if len(conn.splits) > maxConcurrentSplits && conn.handler.limitsEnabled() {
		return fmt.Errorf("split packet: maximum concurrent splits %v reached", maxConcurrentSplits)
	}
	m, ok := conn.splits[p.splitID]
	if !ok {
		m = make([][]byte, p.splitCount)
		conn.splits[p.splitID] = m
	}
	if p.splitIndex > uint32(len(m)-1) {
		// The split index was either negative or was bigger than the slice
		// size, meaning the packet is invalid.
		return fmt.Errorf("split packet: split index %v is out of range (0 - %v)", p.splitIndex, len(m)-1)
	}
	m[p.splitIndex] = p.content

	if slices.ContainsFunc(m, func(i []byte) bool { return len(i) == 0 }) {
		// We haven't yet received all split fragments, so we cannot add the
		// packets together yet.
		return nil
	}
	p.content = slices.Concat(m...)

	delete(conn.splits, p.splitID)
	return conn.receivePacket(p)
}

// sendACK sends an acknowledgement packet containing the packet sequence
// numbers passed. If not successful, an error is returned.
func (conn *Conn) sendACK(packets ...uint24) error {
	defer conn.ackBuf.Reset()
	return conn.sendAcknowledgement(packets, bitFlagACK, conn.ackBuf)
}

// sendNACK sends an acknowledgement packet containing the packet sequence
// numbers passed. If not successful, an error is returned.
func (conn *Conn) sendNACK(packets []uint24) error {
	defer conn.nackBuf.Reset()
	return conn.sendAcknowledgement(packets, bitFlagNACK, conn.nackBuf)
}

// sendAcknowledgement sends an acknowledgement packet with the packets passed,
// potentially sending multiple if too many packets are passed. The bitflag is
// added to the header byte.
func (conn *Conn) sendAcknowledgement(packets []uint24, bitflag byte, buf *bytes.Buffer) error {
	ack := &acknowledgement{packets: packets}

	for len(ack.packets) != 0 {
		buf.WriteByte(bitflag | bitFlagDatagram)
		n := ack.write(buf, conn.effectiveMTU())
		// We managed to write n packets in the ACK with this MTU size, write
		// the next of the packets in a new ACK.
		ack.packets = ack.packets[n:]
		if err := conn.writeTo(buf.Bytes(), conn.raddr); err != nil {
			return fmt.Errorf("send acknowlegement: %w", err)
		}
		buf.Reset()
	}
	return nil
}

// handleACK handles an acknowledgement packet from the other end of the
// connection. These mean that a datagram was successfully received by the
// other end.
func (conn *Conn) handleACK(b []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	ack := &acknowledgement{}
	if err := ack.read(b); err != nil {
		return fmt.Errorf("read ACK: %w", err)
	}

	var newlyAckedBytes int
	for _, sequenceNumber := range ack.packets {
		// If this sequence number was queued for resend, mark it as no longer needed.
		delete(conn.ccNackSet, sequenceNumber)
		if packets, ok := conn.retransmission.acknowledge(sequenceNumber); ok {
			// We don't know the full datagram size here anymore because it has
			// been removed from the resendMap, but we can approximate the
			// contribution by using the effective MTU as MSS.
			newlyAckedBytes += int(conn.effectiveMTU())
			for _, p := range packets {
				returnPacket(p)
				if conn.onACK != nil {
					a, ok := conn.acknowledgements[p.orderIndex]
					if !ok {
						continue
					}
					a.remaining--
					if a.remaining == 0 {
						conn.onACK(a.internalID)
						delete(conn.acknowledgements, p.orderIndex)
					}
				}
			}
		} else if a, ok := conn.oldACKSequences[sequenceNumber]; ok {
			// This sequence number has been deleted from the retransmission map, but we have kept track of it.
			a.remaining--
			if a.remaining == 0 {
				conn.onACK(a.internalID)
				delete(conn.oldACKSequences, sequenceNumber)
			}
		}
	}
	// Congestion control update (UDT-inspired) and pending flush.
	if newlyAckedBytes > 0 {
		// Track the highest acknowledged sequence number in this ACK for UDT updates.
		var lastSeq32 uint32
		for _, s := range ack.packets {
			seq32 := uint32(s)
			if seq32 > lastSeq32 {
				lastSeq32 = seq32
			}
		}

		conn.ccTotalAckedBytes += uint64(newlyAckedBytes)
		// Use the smoothed RTT estimate.
		rtt := conn.retransmission.rtt()
		isContinuous := len(conn.ccPending) > 0
		conn.cc.OnAck(rtt, isContinuous, conn.ccTotalAckedBytes, lastSeq32)
		conn.flushSendQueueLocked()
	}
	return nil
}

// handleNACK handles a negative acknowledgment packet from the other end of
// the connection. These mean that a datagram was found missing.
func (conn *Conn) handleNACK(b []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Rate limit NACK processing to prevent amplification attacks.
	now := time.Now()
	if now.Sub(conn.nackWindowStart) >= time.Second {
		// Reset the rate limit window.
		conn.nackWindowStart = now
		conn.nackBudget = nackBudgetPerSecond
	}
	if conn.nackBudget <= 0 {
		// Budget exhausted: silently drop this NACK to prevent amplification.
		return nil
	}

	nack := &acknowledgement{}
	if err := nack.read(b); err != nil {
		return fmt.Errorf("read NACK: %w", err)
	}

	// Filter to only sequence numbers that actually exist in our retransmission
	// queue. This prevents attackers from requesting resends for packets we
	// never sent or have already been acknowledged.
	validPackets := make([]uint24, 0, len(nack.packets))
	for _, seq := range nack.packets {
		if _, exists := conn.retransmission.unacknowledged[seq]; exists {
			validPackets = append(validPackets, seq)
		}
	}

	if len(validPackets) == 0 {
		return nil
	}

	// Deduct from rate limit budget (only count valid packets).
	conn.nackBudget -= len(validPackets)

	// Packet loss indicated by peer.
	conn.metricsMarkOutLostSeqs(validPackets)
	conn.cc.OnNAK()
	conn.enqueueResendsLocked(validPackets)
	return nil
}

// sendDatagram sends a datagram over the connection that includes the packets
// passed. It is assigned a new sequence number and added to the retransmission.
// Returns the encoded datagram length in bytes on success.
func (conn *Conn) sendDatagram(packets []*packet) (int, error) {
	flags := byte(bitFlagDatagram)
	// Request B (bandwidth) and AS (arrival rate) from receiver during slow start, when we need arrival rate to calculate initial sending rate upon exiting slow start.
	if conn.cc.IsInSlowStart() {
		flags |= bitFlagNeedsBAndAS
	}
	if len(conn.ccPending) > 0 {
		flags |= bitFlagContinuousSend
	}
	// Inform congestion controller that we are sending a datagram (for internal sequence progression).
	conn.cc.OnDatagramSent()
	conn.buf.WriteByte(flags)
	seq := conn.seq.Inc()
	writeUint24(conn.buf, seq)
	for _, pk := range packets {
		pk.write(conn.buf)
	}
	datagramLen := conn.buf.Len()
	defer conn.buf.Reset()

	// Count an outbound transmission attempt for loss ratio accounting.
	conn.metricsIncOutTotal(1)

	// We then re-add the packets to the recovery queue in case the new one gets
	// lost too, in which case we need to resend them again.
	conn.retransmission.add(seq, packets, datagramLen)

	if err := conn.writeTo(conn.buf.Bytes(), conn.raddr); err != nil {
		return 0, fmt.Errorf("send datagram: %w", err)
	}
	return datagramLen, nil
}

// sendUnreliableDatagram sends a datagram over the connection without adding it
// to the retransmission queue. This is used for unreliable packets that should
// not be tracked for acknowledgement or resent on NACK.
func (conn *Conn) sendUnreliableDatagram(packets []*packet) error {
	flags := byte(bitFlagDatagram)
	// Request B (bandwidth) and AS (arrival rate) from receiver during slow start, when we need arrival rate to calculate initial sending rate upon exiting slow start.
	if conn.cc.IsInSlowStart() {
		flags |= bitFlagNeedsBAndAS
	}
	if len(conn.ccPending) > 0 {
		flags |= bitFlagContinuousSend
	}
	// Inform congestion controller that we are sending a datagram (for internal sequence progression).
	conn.cc.OnDatagramSent()
	conn.buf.WriteByte(flags)
	seq := conn.seq.Inc()
	writeUint24(conn.buf, seq)
	for _, pk := range packets {
		pk.write(conn.buf)
	}
	defer conn.buf.Reset()

	// Count an outbound transmission attempt for loss ratio accounting.
	conn.metricsIncOutTotal(1)

	// Unreliable packets are not added to the retransmission queue.
	// They are fire-and-forget.

	if err := conn.writeTo(conn.buf.Bytes(), conn.raddr); err != nil {
		return fmt.Errorf("send unreliable datagram: %w", err)
	}
	return nil
}

// writeTo calls WriteTo on the underlying UDP connection and returns an error
// only if the error returned is net.ErrClosed. In any other case, the error
// is logged but not returned. This is done because at this stage, packets
// being lost to an error can be recovered through resending.
func (conn *Conn) writeTo(p []byte, raddr net.Addr) error {
	if _, err := conn.conn.WriteTo(p, raddr); errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("write to: %w", err)
	} else if err != nil {
		conn.handler.log().Error("write to: "+err.Error(), "raddr", raddr.String())
	}
	return nil
}

type PendingConnection struct {
	CreatedAt time.Time
	Cookie    uint32
}

var startTime = time.Now()

// timestamp returns a timestamp in milliseconds.
func timestamp() int64 {
	return time.Since(startTime).Milliseconds()
}

// canSendLocked returns true if we can send another new datagram under the current cwnd.
// It is assumed that the connection's mutex (conn.mu) is already held by the caller.
func (conn *Conn) canSendLocked() bool {
	// Unified gating: rely on per-tick budget from UDT controller
	return conn.sendBudget > 0
}

// queueOrSend enqueues the packet if cwnd is full, otherwise sends it immediately.
// It is assumed that the connection's mutex (conn.mu) is already held by the caller.
func (conn *Conn) queueOrSend(pk *packet) error {
	if conn.canSendLocked() {
		sentLen, err := conn.sendDatagram([]*packet{pk})
		if err != nil {
			return err
		}
		// Always reduce budgets and notify congestion controller after sending.
		conn.cc.OnSendBytes(sentLen)
		conn.sendBudget -= sentLen
		if conn.sendBudget < 0 {
			conn.sendBudget = 0
		}
		return nil
	}
	conn.ccPending = append(conn.ccPending, pk)
	return nil
}

// flushSendQueueLocked attempts to send queued packets while the congestion window allows.
// It is assumed that the connection's mutex (conn.mu) is already held by the caller.
func (conn *Conn) flushSendQueueLocked() {
	for len(conn.ccPending) > 0 && conn.canSendLocked() {
		pk := conn.ccPending[0]
		conn.ccPending = conn.ccPending[1:]
		sentLen, err := conn.sendDatagram([]*packet{pk})
		if err != nil {
			// On error, stop flushing; push pk back and break.
			conn.ccPending = append([]*packet{pk}, conn.ccPending...)
			break
		}
		// Always reduce budgets and notify congestion controller after sending.
		conn.cc.OnSendBytes(sentLen)
		conn.sendBudget -= sentLen
		if conn.sendBudget < 0 {
			conn.sendBudget = 0
		}
		// If budget exhausted, stop.
		if conn.sendBudget == 0 {
			break
		}
	}
}

// enqueueResendsLocked inserts sequence numbers into the paced resend queue.
// It is assumed that the connection's mutex (conn.mu) is already held by the caller.
// Returns the number of sequence numbers that were actually enqueued.
func (conn *Conn) enqueueResendsLocked(numbers []uint24) int {
	enqueued := 0
	for _, seq := range numbers {
		if _, ok := conn.ccNackSet[seq]; ok {
			continue
		}
		// Limit queue size to prevent memory exhaustion from excessive NACKs.
		if len(conn.ccNackQueue) >= maxNackQueueSize {
			break
		}
		conn.ccNackSet[seq] = struct{}{}
		conn.ccNackQueue = append(conn.ccNackQueue, seq)
		enqueued++
	}
	return enqueued
}

// flushResendQueueLocked resends a limited number of queued sequence numbers to avoid bursts.
// It is assumed that the connection's mutex (conn.mu) is already held by the caller.
func (conn *Conn) flushResendQueueLocked() {
	if len(conn.ccNackQueue) == 0 {
		return
	}
	// Use UDT-provided retransmission byte budget for this tick.
	for conn.resendBudget > 0 && len(conn.ccNackQueue) > 0 {
		seq := conn.ccNackQueue[0]
		conn.ccNackQueue = conn.ccNackQueue[1:]
		// If this seq was already acked/removed, skip.
		if _, ok := conn.ccNackSet[seq]; !ok {
			continue
		}
		delete(conn.ccNackSet, seq)
		packets, ok := conn.retransmission.retransmit(seq)
		if !ok {
			// It may have been acknowledged already.
			continue
		}

		sentLen, err := conn.sendDatagram(packets)
		if err != nil {
			// Failed to send: push back to the front to retry later and stop.
			conn.ccNackQueue = append([]uint24{seq}, conn.ccNackQueue...)
			conn.ccNackSet[seq] = struct{}{}
			break
		}
		// Notify congestion controller and reduce retransmission budget.
		conn.cc.OnSendBytes(sentLen)
		conn.resendBudget -= sentLen
		if conn.resendBudget < 0 {
			conn.resendBudget = 0
		}
	}
}

// (Congestion control handlers are implemented via the congestion.Controller interface)

// --- Internal metrics helpers ---

func (conn *Conn) metricsIncOutTotal(n int) {
	if n <= 0 {
		return
	}
	conn.lossMetricsMu.Lock()
	conn.lossOutTotalBuckets[conn.lossMetricsBucket] += uint32(n)
	conn.lossMetricsMu.Unlock()
}

// nolint:unused
func (conn *Conn) metricsIncOutLost(n int) {
	if n <= 0 {
		return
	}
	conn.lossMetricsMu.Lock()
	conn.lossOutLostBuckets[conn.lossMetricsBucket] += uint32(n)
	conn.lossMetricsMu.Unlock()
}

func (conn *Conn) metricsIncInTotal(n int) {
	if n <= 0 {
		return
	}
	conn.lossMetricsMu.Lock()
	conn.lossInTotalBuckets[conn.lossMetricsBucket] += uint32(n)
	conn.lossMetricsMu.Unlock()
}

func (conn *Conn) metricsIncInLost(n int) {
	if n <= 0 {
		return
	}
	conn.lossMetricsMu.Lock()
	conn.lossInLostBuckets[conn.lossMetricsBucket] += uint32(n)
	conn.lossMetricsMu.Unlock()
}

// metricsMarkOutLostSeqs increments the outbound lost bucket for sequence
// numbers that have not been counted recently (deduplicated within ~1s).
func (conn *Conn) metricsMarkOutLostSeqs(seqs []uint24) {
	if len(seqs) == 0 {
		return
	}
	now := time.Now().UnixNano()
	conn.lossMetricsMu.Lock()
	for _, s := range seqs {
		if ts, ok := conn.lostOutRecent[s]; ok && now-ts < int64(time.Second) {
			continue
		}
		conn.lostOutRecent[s] = now
		conn.lossOutLostBuckets[conn.lossMetricsBucket]++
	}
	conn.lossMetricsMu.Unlock()
}

// metricsMarkInLostSeqs increments the inbound lost bucket for sequence
// numbers that have not been counted recently (deduplicated within ~1s).
func (conn *Conn) metricsMarkInLostSeqs(seqs []uint24) {
	if len(seqs) == 0 {
		return
	}
	now := time.Now().UnixNano()
	conn.lossMetricsMu.Lock()
	for _, s := range seqs {
		if ts, ok := conn.lostInRecent[s]; ok && now-ts < int64(time.Second) {
			continue
		}
		conn.lostInRecent[s] = now
		conn.lossInLostBuckets[conn.lossMetricsBucket]++
	}
	conn.lossMetricsMu.Unlock()
}
