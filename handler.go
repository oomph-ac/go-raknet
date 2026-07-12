package raknet

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/sandertv/go-raknet/internal"
	"github.com/sandertv/go-raknet/message"
)

type connectionHandler interface {
	handle(conn *Conn, b []byte, reliability byte) (handled bool, err error)
	limitsEnabled() bool
	close(conn *Conn)
	log() *slog.Logger
}

type listenerConnectionHandler struct {
	listener *Listener

	currentCookieSalt uint64
	prevCookieSalt    uint64
}

var (
	errUnexpectedAdditionalNIC = errors.New("unexpected additional NEW_INCOMING_CONNECTION packet")
)

func (h *listenerConnectionHandler) log() *slog.Logger {
	return h.listener.conf.ErrorLog
}

func (h *listenerConnectionHandler) limitsEnabled() bool {
	return true
}

func (h *listenerConnectionHandler) close(conn *Conn) {
	h.listener.connections.Delete(resolve(conn.raddr))
}

// cleanup periodically rotates the salts used to validate connection cookies.
func (h *listenerConnectionHandler) cleanup(done <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			h.prevCookieSalt = h.currentCookieSalt
			h.currentCookieSalt = rand.Uint64()
		}
	}
}

func (h *listenerConnectionHandler) handleUnconnected(b []byte, addr net.Addr) error {
	switch b[0] {
	case message.IDUnconnectedPing, message.IDUnconnectedPingOpenConnections:
		return h.handleUnconnectedPing(b[1:], addr)
	case message.IDOpenConnectionRequest1:
		return h.handleOpenConnectionRequest1(b[1:], addr)
	case message.IDOpenConnectionRequest2:
		return h.handleOpenConnectionRequest2(b[1:], addr)
	}
	if b[0]&bitFlagDatagram != 0 {
		return nil
	}
	return fmt.Errorf("unknown unconnected packet (id=%x, len=%v)", b[0], len(b))
}

// handleUnconnectedPing handles an unconnected ping packet stored in buffer b,
// coming from an address.
func (h *listenerConnectionHandler) handleUnconnectedPing(b []byte, addr net.Addr) error {
	pk := &message.UnconnectedPing{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read UNCONNECTED_PING: %w", err)
	}

	data, _ := (&message.UnconnectedPong{
		ServerGUID: h.listener.id,
		PingTime:   pk.PingTime,
		Data:       *h.listener.pongData.Load(),
	}).MarshalBinary()
	_, err := h.listener.conn.WriteTo(data, addr)

	return err
}

// handleOpenConnectionRequest1 handles an open connection request 1 packet stored in buffer b, coming from an address.
func (h *listenerConnectionHandler) handleOpenConnectionRequest1(b []byte, addr net.Addr) error {
	// Create an inital connection for the client with this address. If a connection already exists for the given address,
	// return an error and don't do anything.
	resolvedAddr := resolve(addr)
	if _, foundConn := h.listener.connections.Load(resolvedAddr); foundConn {
		return fmt.Errorf("handle OPEN_CONNECTION_REQUEST_1: connection already exists for address %s", addr.String())
	}

	pk := &message.OpenConnectionRequest1{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read OPEN_CONNECTION_REQUEST_1: %w", err)
	}

	// If the client wants an MTU size smaller than what we support, we can't let them use it since it would cause
	// large overhead due to fragmentation. However, if the MTU is greater than what we support, we can
	// still negotiate it.
	if pk.MTU < minMTUSize {
		return fmt.Errorf("handle OPEN_CONNECTION_REQUEST_1: MTU is less than minimum MTU size %v", minMTUSize)
	}

	mtuSize := min(pk.MTU, maxMTUSize)
	if pk.ClientProtocol != protocolVersion {
		data, _ := (&message.IncompatibleProtocolVersion{ServerGUID: h.listener.id, ServerProtocol: protocolVersion}).MarshalBinary()
		_, _ = h.listener.conn.WriteTo(data, addr)
		return fmt.Errorf("handle OPEN_CONNECTION_REQUEST_1: incompatible protocol version %v (listener protocol = %v)", pk.ClientProtocol, protocolVersion)
	}

	addrCookie := internal.Cookie(addr.(*net.UDPAddr), h.currentCookieSalt)
	data, _ := (&message.OpenConnectionReply1{
		ServerGUID:        h.listener.id,
		Cookie:            addrCookie,
		ServerHasSecurity: !h.listener.conf.DisableCookies,
		MTU:               mtuSize,
	}).MarshalBinary()
	_, err := h.listener.conn.WriteTo(data, addr)

	return err
}

// handleOpenConnectionRequest2 handles an open connection request 2 packet
// stored in buffer b, coming from an address.
func (h *listenerConnectionHandler) handleOpenConnectionRequest2(b []byte, addr net.Addr) error {
	// Check if there is a pending connection for the given address. If there is not, then this open connection request is invalid.
	resolvedAddr := resolve(addr)
	if _, foundConn := h.listener.connections.Load(resolvedAddr); foundConn {
		return fmt.Errorf("handle OPEN_CONNECTION_REQUEST_2: connection already exists for address %s", addr.String())
	}

	pk := &message.OpenConnectionRequest2{ServerHasSecurity: !h.listener.conf.DisableCookies}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read OPEN_CONNECTION_REQUEST_2: %w", err)
	}
	if pk.MTU < minMTUSize {
		return fmt.Errorf("handle OPEN_CONNECTION_REQUEST_2: MTU is less than minimum MTU size %v", minMTUSize)
	}

	if !h.listener.conf.DisableCookies {
		udpAddr, _ := addr.(*net.UDPAddr)
		cookie1, cookie2 := internal.Cookie(udpAddr, h.currentCookieSalt), internal.Cookie(udpAddr, h.prevCookieSalt)
		isFirstCookie, isSecondCookie := pk.Cookie == cookie1, pk.Cookie == cookie2

		// Reject missing, invalid, or ambiguous cookies.
		if isFirstCookie == isSecondCookie {
			return nil
		}
	}

	mtuSize := min(pk.MTU, maxMTUSize)
	conn := newConn(h.listener.conn, addr, mtuSize, h)
	conn.setIncomingDatagramErrorHandler(func(err error) {
		addrStr := "unknown"
		if conn.raddr != nil {
			addrStr = conn.raddr.String()
			h.listener.sec.block(conn.raddr)
		}
		h.listener.conf.ErrorLog.Error("handle packet: "+err.Error(), "raddr", addrStr, "block-duration", max(0, h.listener.conf.BlockDuration))
	})
	if f := filter; f != nil {
		if err := f.RegisterConnection(resolvedAddr); err != nil {
			return fmt.Errorf("register connection: %w", err)
		}
	}

	data, _ := (&message.OpenConnectionReply2{ServerGUID: h.listener.id, ClientAddress: resolvedAddr, MTU: mtuSize}).MarshalBinary()
	if _, err := h.listener.conn.WriteTo(data, addr); err != nil {
		return fmt.Errorf("send OPEN_CONNECTION_REPLY_2: %w", err)
	}

	h.listener.connections.Store(resolvedAddr, conn)

	return nil
}

func (h *listenerConnectionHandler) handle(conn *Conn, b []byte, _ byte) (handled bool, err error) {
	handled = true
	switch b[0] {
	case message.IDConnectionRequest:
		return true, h.handleConnectionRequest(conn, b[1:])
	case message.IDConnectionRequestAccepted:
		return true, nil
	case message.IDNewIncomingConnection:
		return true, h.handleNewIncomingConnection(conn, b[1:])
	case message.IDConnectedPing:
		return true, handleConnectedPing(conn, b[1:])
	case message.IDConnectedPong:
		return true, handleConnectedPong(conn, b[1:])
	case message.IDDisconnectNotification:
		conn.closeImmediately()
		return true, nil
	case message.IDDetectLostConnections:
		return true, nil
	default:
		handled = false
	}
	return
}

// handleConnectionRequest handles a connection request packet inside of buffer
// b. An error is returned if the packet was invalid.
func (h *listenerConnectionHandler) handleConnectionRequest(conn *Conn, b []byte) error {
	if conn.receivedConnectionRequest {
		return fmt.Errorf("handle CONNECTION_REQUEST: client already sent a connection request to the server")
	}
	pk := &message.ConnectionRequest{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read CONNECTION_REQUEST: %w", err)
	}
	conn.receivedConnectionRequest = true

	err := conn.send(&message.ConnectionRequestAccepted{
		ClientAddress: resolve(conn.raddr),
		SystemAddresses: [20]netip.AddrPort{
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
			netip.MustParseAddrPort("0.0.0.0:0"),
		},
		PingTime: pk.RequestTime,
		PongTime: pk.RequestTime,
	})

	return err
}

// handleNewIncomingConnection handles an incoming connection packet from the
// client, finalising the Conn.
func (h *listenerConnectionHandler) handleNewIncomingConnection(conn *Conn, _ []byte) error {
	select {
	case <-conn.connected:
		return errUnexpectedAdditionalNIC
	default:
		if !conn.receivedConnectionRequest {
			go conn.closeImmediately()
			return fmt.Errorf("handle NEW_INCOMING_CONNECTION: no connection request received")
		}
		close(conn.connected)
		return nil
	}
}

type dialerConnectionHandler struct{ l *slog.Logger }

func (h dialerConnectionHandler) log() *slog.Logger {
	return h.l
}

func (h dialerConnectionHandler) close(conn *Conn) {
	_ = conn.conn.Close()
}

func (h dialerConnectionHandler) limitsEnabled() bool {
	return false
}

func (h dialerConnectionHandler) handle(conn *Conn, b []byte, _ byte) (handled bool, err error) {
	handled = true
	switch b[0] {
	case message.IDConnectionRequest:
		return true, nil
	case message.IDConnectionRequestAccepted:
		return true, h.handleConnectionRequestAccepted(conn, b[1:])
	case message.IDNewIncomingConnection:
		return true, nil
	case message.IDConnectedPing:
		return true, handleConnectedPing(conn, b[1:])
	case message.IDConnectedPong:
		return true, nil
	case message.IDDisconnectNotification:
		conn.closeImmediately()
		return true, nil
	case message.IDDetectLostConnections:
		return true, nil
	default:
		handled = false
	}

	return
}

// handleConnectionRequestAccepted handles a serialised connection request
// accepted packet in b, and returns an error if not successful.
func (h dialerConnectionHandler) handleConnectionRequestAccepted(conn *Conn, b []byte) error {
	pk := &message.ConnectionRequestAccepted{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read CONNECTION_REQUEST_ACCEPTED: %w", err)
	}

	select {
	case <-conn.connected:
		return nil
	default:
	}

	// Make sure to send NewIncomingConnection before closing conn.connected.
	systemAddrs := [20]netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", conn.LocalAddr().(*net.UDPAddr).Port))}
	for index := 1; index < len(systemAddrs); index++ {
		systemAddrs[index] = netip.MustParseAddrPort("0.0.0.0:0")
	}

	err := conn.send(&message.NewIncomingConnection{
		ServerAddress:   resolve(conn.raddr),
		PingTime:        pk.PongTime,
		PongTime:        timestamp(),
		SystemAddresses: systemAddrs,
	})
	close(conn.connected)

	return err
}

// handleConnectedPing handles a connected ping packet inside of buffer b. An
// error is returned if the packet was invalid.
func handleConnectedPing(conn *Conn, b []byte) error {
	pk := &message.ConnectedPing{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read CONNECTED_PING: %w", err)
	}
	err := conn.sendWithReliability(&message.ConnectedPong{PingTime: pk.PingTime, PongTime: timestamp()}, reliabilityUnreliable)

	return err
}

// handleConnectedPong ...
func handleConnectedPong(conn *Conn, b []byte) error {
	pk := &message.ConnectedPong{}
	if err := pk.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("read CONNECTED_PONG: %w", err)
	}
	conn.rawLatency.Store(timestamp() - pk.PingTime)
	return nil
}
