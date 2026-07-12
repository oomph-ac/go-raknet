package raknet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/go-raknet/message"
)

// ampCountingConn wraps a net.Conn to count bytes read and written.
type ampCountingConn struct {
	net.Conn
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func (c *ampCountingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bytesRead.Add(int64(n))
	}
	return n, err
}

func (c *ampCountingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bytesWritten.Add(int64(n))
	}
	return n, err
}

// ampConnState mirrors connState from dial.go for the amplification test.
type ampConnState struct {
	conn   *ampCountingConn
	raddr  net.Addr
	id     int64
	mtu    uint16
	ticker *time.Ticker

	serverSecurity bool
	cookie         uint32

	// observedSeqs tracks sequence numbers we've observed from the server.
	// These are sequences that exist in the server's retransmission queue
	// since we never ACK them.
	observedSeqs []uint24
	// highestSeq tracks the highest sequence number we've seen from the server.
	highestSeq uint24
}

// TestNACKAmplification exercises the NACK handling path end-to-end against a
// local server and verifies the amplification mitigations (budget, queue cap,
// and pacing) bound the amount of traffic we can induce with NACKs.
func TestNACKAmplification(t *testing.T) {
	serverAddr := os.Getenv("NACK_AMP_SERVER_ADDR")
	if serverAddr == "" {
		t.Skip("set NACK_AMP_SERVER_ADDR to a running RakNet server to run this test")
	}

	// Parse number of connections from environment variable (default 1)
	numConnectionsStr := os.Getenv("NACK_AMP_CONNECTIONS")
	numConnections := 1
	if numConnectionsStr != "" {
		if parsed, err := strconv.Atoi(numConnectionsStr); err == nil && parsed > 0 {
			numConnections = parsed
		}
	}
	t.Logf("Running test with %d connections", numConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type connResult struct {
		handshakeRead    int64
		handshakeWritten int64
		attackRead       int64
		attackWritten    int64
		resendCount      int
		err              error
	}

	results := make([]connResult, numConnections)
	var wg sync.WaitGroup

	wg.Add(numConnections)
	for i := 0; i < numConnections; i++ {
		go func(connIdx int) {
			defer wg.Done()

			// Create UDP connection to the server (mirrors dial.go's dialer.dial).
			rawConn, err := (&net.Dialer{}).DialContext(ctx, "udp", serverAddr)
			if err != nil {
				results[connIdx] = connResult{err: fmt.Errorf("failed to dial UDP: %w", err)}
				return
			}

			conn := &ampCountingConn{Conn: rawConn}
			defer conn.Close()

			// Set connection deadline based on context (mirrors dial.go).
			if deadline, ok := ctx.Deadline(); ok {
				_ = conn.SetDeadline(deadline)
			}

			// Create connection state mirroring dial.go's connState.
			state := &ampConnState{
				conn:         conn,
				raddr:        conn.RemoteAddr(),
				id:           rand.Int64(),
				ticker:       time.NewTicker(time.Second / 2),
				observedSeqs: make([]uint24, 0, 256),
			}
			defer state.ticker.Stop()

			// Phase 1: MTU Discovery
			// Retry loop matching dial.go behavior.
			for {
				_ = conn.SetReadDeadline(time.Time{})
				if deadline, ok := ctx.Deadline(); ok {
					_ = conn.SetDeadline(deadline)
				}

				if err = state.ampDiscoverMTU(ctx); err != nil {
					results[connIdx] = connResult{err: fmt.Errorf("MTU discovery failed: %w", err)}
					return
				}

				// Phase 2: Open Connection
				err = state.ampOpenConnection(ctx)
				if err != nil {
					if errors.Is(err, errReply2Timeout) {
						continue
					}
					results[connIdx] = connResult{err: fmt.Errorf("open connection failed: %w", err)}
					return
				}
				break
			}

			// Record bytes at end of handshake phase.
			handshakeRead := conn.bytesRead.Load()
			handshakeWritten := conn.bytesWritten.Load()

			// Phase 3: Sending ConnectionRequest and NewIncomingConnection
			// Send ConnectionRequest (as reliable-ordered datagram) - mirrors dial.go's connect().
			seq := uint24(0)
			messageIdx := uint24(0)
			orderIdx := uint24(0)

			spamSeqCount := 2047
			connReq, _ := (&message.ConnectionRequest{
				ClientGUID:  state.id,
				RequestTime: timestamp(),
			}).MarshalBinary()
			for range spamSeqCount {
				if err := ampSendReliableOrdered(conn, connReq, &seq, &messageIdx, &orderIdx); err != nil {
					results[connIdx] = connResult{err: fmt.Errorf("failed to send ConnectionRequest: %w", err)}
					return
				}
			}

			// Send NewIncomingConnection - mirrors dial.go's handleConnectionRequestAccepted.
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			systemAddrs := [20]netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", localAddr.Port))}
			for i := 1; i < len(systemAddrs); i++ {
				systemAddrs[i] = netip.MustParseAddrPort("0.0.0.0:0")
			}

			newIncoming, _ := (&message.NewIncomingConnection{
				ServerAddress:   netip.MustParseAddrPort(serverAddr),
				PingTime:        0,
				PongTime:        timestamp(),
				SystemAddresses: systemAddrs,
			}).MarshalBinary()

			if err := ampSendReliableOrdered(conn, newIncoming, &seq, &messageIdx, &orderIdx); err != nil {
				results[connIdx] = connResult{err: fmt.Errorf("failed to send NewIncomingConnection: %w", err)}
				return
			}

			// Phase 4: Collecting observed sequence numbers (commented out as in original)
			// Prepare for the amplification attack.
			preAttackRead := conn.bytesRead.Load()
			preAttackWritten := conn.bytesWritten.Load()

			// Phase 5: Sending targeted NACKs
			minSeq, maxSeq := uint24(0), uint24(8000)
			seqTotal := uint24(8001)
			for range 100 {
				//_ = ampSendReliableOrdered(conn, connReq, &seq, &messageIdx, &orderIdx)
				_ = ampSendNACKRange(conn, minSeq, maxSeq)
				minSeq += seqTotal
				maxSeq += seqTotal
			}

			// Phase 6: Measuring retransmissions
			knownSeqs := make(map[uint24]struct{})

			resendCtx, cancelResend := context.WithTimeout(ctx, 15*time.Second)
			resendCount, err := ampCountResends(resendCtx, conn, knownSeqs)
			cancelResend()
			if err != nil {
				results[connIdx] = connResult{err: fmt.Errorf("failed while measuring resends: %w", err)}
				return
			}

			attackRead := conn.bytesRead.Load() - preAttackRead
			attackWritten := conn.bytesWritten.Load() - preAttackWritten
			if attackWritten == 0 {
				results[connIdx] = connResult{err: errors.New("no bytes written during attack phase")}
				return
			}

			results[connIdx] = connResult{
				handshakeRead:    handshakeRead,
				handshakeWritten: handshakeWritten,
				attackRead:       attackRead,
				attackWritten:    attackWritten,
				resendCount:      resendCount,
			}
		}(i)
	}

	wg.Wait()

	// Aggregate results from all connections
	var totalHandshakeRead, totalHandshakeWritten, totalAttackRead, totalAttackWritten, totalResendCount int64
	for i, result := range results {
		if result.err != nil {
			t.Fatalf("connection %d failed: %v", i, result.err)
		}
		totalHandshakeRead += result.handshakeRead
		totalHandshakeWritten += result.handshakeWritten
		totalAttackRead += result.attackRead
		totalAttackWritten += result.attackWritten
		totalResendCount += int64(result.resendCount)
	}

	t.Logf("server: %.2fMB, client: %.2fMB", float64(totalAttackRead)/1024/1024, float64(totalAttackWritten)/1024/1024)

	if totalAttackWritten == 0 {
		t.Fatalf("no bytes written during attack phase across all connections")
	}

	ampFactor := float64(totalAttackRead) / float64(totalAttackWritten)
	t.Logf("Overall amplification factor: %.2fx", ampFactor)

	// The server budget should cap retransmissions at nackBudgetPerSecond per second.
	// Since we have multiple connections, we scale the expected budget accordingly.
	expectedMaxResends := int64(nackBudgetPerSecond) * int64(numConnections)
	if totalResendCount > expectedMaxResends {
		t.Fatalf("expected at most %d resends due to budget (%d per connection), got %d", expectedMaxResends, nackBudgetPerSecond, totalResendCount)
	}

	// For the byte bound check, we use a conservative estimate based on maximum MTU.
	maxExpectedBytes := int64(nackBudgetPerSecond) * int64(1492) * int64(numConnections) // 1492 is max MTU from mtuSizes
	if totalAttackRead > maxExpectedBytes {
		t.Fatalf("amplification exceeded bound: read %d bytes (max expected %d)", totalAttackRead, maxExpectedBytes)
	}
}

// ampDiscoverMTU mirrors connState.discoverMTU from dial.go.
func (state *ampConnState) ampDiscoverMTU(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go state.ampRequest1(ctx, mtuSizes)

	b := make([]byte, 1492)
read_loop:
	for {
		n, err := state.conn.Read(b)
		if err != nil || n == 0 {
			return err
		}
		switch b[0] {
		case message.IDOpenConnectionReply1:
			response := &message.OpenConnectionReply1{}
			if err := response.UnmarshalBinary(b[1:n]); err != nil {
				if errors.Is(err, message.ErrorInvalidUnconnectedMessageSequence) {
					continue read_loop
				}
				return fmt.Errorf("read open connection reply 1: %w", err)
			}
			state.serverSecurity, state.cookie = response.ServerHasSecurity, response.Cookie
			state.mtu = response.MTU
			return nil
		case message.IDIncompatibleProtocolVersion:
			response := &message.IncompatibleProtocolVersion{}
			if err := response.UnmarshalBinary(b[1:n]); err != nil {
				continue read_loop
			}
			return fmt.Errorf("mismatched protocol: client protocol = %v, server protocol = %v", protocolVersion, response.ServerProtocol)
		}
	}
}

// ampRequest1 mirrors connState.request1 from dial.go.
func (state *ampConnState) ampRequest1(ctx context.Context, sizes []uint16) {
	state.ticker.Reset(3 * time.Second)
	for _, size := range sizes {
		for range 3 {
			state.ampOpenConnectionRequest1(size)
			select {
			case <-state.ticker.C:
				continue
			case <-ctx.Done():
				return
			}
		}
	}
}

// ampOpenConnectionRequest1 mirrors connState.openConnectionRequest1 from dial.go.
func (state *ampConnState) ampOpenConnectionRequest1(mtu uint16) {
	data, _ := (&message.OpenConnectionRequest1{ClientProtocol: protocolVersion, MTU: mtu}).MarshalBinary()
	_, _ = state.conn.Write(data)
}

// ampOpenConnection mirrors connState.openConnection from dial.go.
func (state *ampConnState) ampOpenConnection(ctx context.Context) error {
	state.ampOpenConnectionRequest2(state.mtu)

	_ = state.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	b := make([]byte, 65535)
	for {
		n, err := state.conn.Read(b)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return errReply2Timeout
			}
			return err
		}
		if n == 0 {
			continue
		}
		if b[0] != message.IDOpenConnectionReply2 {
			continue
		}
		pk := &message.OpenConnectionReply2{}
		if err = pk.UnmarshalBinary(b[1:n]); err != nil {
			if errors.Is(err, message.ErrorInvalidUnconnectedMessageSequence) {
				continue
			}
			return fmt.Errorf("read open connection reply 2: %w", err)
		}
		//state.mtu = pk.MTU
		_ = state.conn.SetReadDeadline(time.Time{})
		return nil
	}
}

// ampOpenConnectionRequest2 mirrors connState.openConnectionRequest2 from dial.go.
func (state *ampConnState) ampOpenConnectionRequest2(mtu uint16) {
	data, _ := (&message.OpenConnectionRequest2{
		ServerAddress:     resolve(state.raddr),
		MTU:               mtu,
		ClientGUID:        state.id,
		ServerHasSecurity: state.serverSecurity,
		Cookie:            state.cookie,
	}).MarshalBinary()
	_, _ = state.conn.Write(data)
}

// ampSendReliableOrdered sends a packet with reliable-ordered reliability.
func ampSendReliableOrdered(conn *ampCountingConn, content []byte, seq, messageIdx, orderIdx *uint24) error {
	buf := bytes.NewBuffer(nil)

	// Datagram header.
	buf.WriteByte(bitFlagDatagram | bitFlagNeedsBAndAS)

	// Sequence number (24-bit little endian).
	writeUint24(buf, *seq)
	*seq++

	// Packet header: reliability (reliable ordered = 3) << 5.
	buf.WriteByte(reliabilityReliableOrdered << 5)

	// Content length in bits (big endian).
	contentLenBits := uint16(len(content) << 3)
	binary.Write(buf, binary.BigEndian, contentLenBits)

	// Message index (24-bit little endian).
	writeUint24(buf, *messageIdx)
	*messageIdx++

	// Order index (24-bit little endian).
	writeUint24(buf, *orderIdx)
	*orderIdx++

	// Order channel (1 byte).
	buf.WriteByte(0)

	// Content.
	buf.Write(content)

	_, err := conn.Write(buf.Bytes())
	return err
}

// ampSendNACKRange sends a NACK packet requesting retransmission of a range of sequences.
func ampSendNACKRange(conn *ampCountingConn, startSeq, endSeq uint24) error {
	buf := bytes.NewBuffer(nil)

	// NACK header.
	buf.WriteByte(bitFlagNACK | bitFlagDatagram)

	// Record count (1 record for a range).
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Record type: range (0x00).
	buf.WriteByte(packetRange)

	// Start sequence (24-bit little endian).
	writeUint24(buf, startSeq)

	// End sequence (24-bit little endian).
	writeUint24(buf, endSeq)

	_, err := conn.Write(buf.Bytes())
	return err
}

// ampSendSingleNACK sends a NACK packet requesting retransmission of a single sequence.
func ampSendSingleNACK(conn *ampCountingConn, seq uint24) error {
	buf := bytes.NewBuffer(nil)

	// NACK header.
	buf.WriteByte(bitFlagNACK | bitFlagDatagram)

	// Record count (1 record).
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Record type: single (0x01).
	buf.WriteByte(packetSingle)

	// Sequence (24-bit little endian).
	writeUint24(buf, seq)

	_, err := conn.Write(buf.Bytes())
	return err
}

// ampSendACKRange sends a ACK packet requesting retransmission of a range of sequences.
func ampSendACKRange(conn *ampCountingConn, startSeq, endSeq uint24) error {
	buf := bytes.NewBuffer(nil)

	// ACK header.
	buf.WriteByte(bitFlagACK | bitFlagDatagram)

	// Record count (1 record for a range).
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Record type: range (0x00).
	buf.WriteByte(packetRange)

	// Start sequence (24-bit little endian).
	writeUint24(buf, startSeq)

	// End sequence (24-bit little endian).
	writeUint24(buf, endSeq)

	_, err := conn.Write(buf.Bytes())
	return err
}

// ampSendSingleACK sends a ACK packet acknowledging a single sequence.
func ampSendSingleACK(conn *ampCountingConn, seq uint24) error {
	buf := bytes.NewBuffer(nil)

	// ACK header.
	buf.WriteByte(bitFlagACK | bitFlagDatagram)

	// Record count (1 record).
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Record type: single (0x01).
	buf.WriteByte(packetSingle)

	// Sequence (24-bit little endian).
	writeUint24(buf, seq)

	_, err := conn.Write(buf.Bytes())
	return err
}

// ampCollectSequences reads datagrams from the server and records unique sequence numbers.
func ampCollectSequences(ctx context.Context, conn *ampCountingConn, state *ampConnState, target int) (map[uint24]int, error) {
	seqCounts := make(map[uint24]int, target)
	buf := make([]byte, 65535)

	for len(seqCounts) < target {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-ctx.Done():
					return seqCounts, ctx.Err()
				default:
					continue
				}
			}
			return seqCounts, err
		}
		if n < 4 || buf[0]&bitFlagDatagram == 0 {
			continue
		}
		seq := loadUint24(buf[1:])
		if _, ok := seqCounts[seq]; !ok {
			state.observedSeqs = append(state.observedSeqs, seq)
			if seq > state.highestSeq {
				state.highestSeq = seq
			}
		}
		seqCounts[seq]++
	}
	_ = conn.SetReadDeadline(time.Time{})
	return seqCounts, nil
}

// ampCountResends drains datagrams for the provided duration and counts how many match known sequences.
func ampCountResends(ctx context.Context, conn *ampCountingConn, known map[uint24]struct{}) (int, error) {
	buf := make([]byte, 65535)
	resendCount := 0

	for {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Time{})
			return resendCount, nil
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return resendCount, err
		}
		if n < 2 {
			continue
		}
		/* if buf[0]&bitFlagDatagram != 0 && buf[1] == message.IDDisconnectNotification {
			return resendCount, nil
		} */
		if n < 4 || buf[0]&bitFlagDatagram == 0 {
			continue
		}
		seq := loadUint24(buf[1:])
		if _, ok := known[seq]; ok {
			resendCount++
		}
	}
}
