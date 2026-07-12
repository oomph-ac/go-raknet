package raknet

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sandertv/go-raknet/message"
)

// UpstreamPacketListener allows for a custom PacketListener implementation.
type UpstreamPacketListener interface {
	ListenPacket(network, address string) (net.PacketConn, error)
}

// ListenConfig may be used to pass additional configuration to a Listener.
type ListenConfig struct {
	// ErrorLog is a logger that errors from packet decoding are logged to. By
	// default, ErrorLog is set to a new slog.Logger with a slog.Handler that
	// is always disabled. Error messages are thus not logged by default.
	ErrorLog *slog.Logger

	// UpstreamPacketListener adds an abstraction for net.ListenPacket.
	UpstreamPacketListener UpstreamPacketListener

	// ReusePortSockets specifies how many UDP sockets should be opened for a
	// single listener. Values less than 1 default to 1.
	//
	// On Linux, values greater than 1 use SO_REUSEPORT for the default socket
	// listener. When UpstreamPacketListener is set, this value controls how many
	// times ListenPacket is called.
	ReusePortSockets int

	// DisableCookies specifies if cookies should be generated and verified for
	// new incoming connections. This is a security measure against IP spoofing,
	// but some server providers (OVH in particular) have existing protection
	// systems that interfere with this. In this case, DisableCookies should be
	// set to true.
	DisableCookies bool
	// BlockDuration specifies how long IP addresses should be blocked if an
	// error is encountered during the handling of packets from an address.
	// BlockDuration defaults to 10s. If set to a negative value, IP addresses
	// are never blocked on errors.
	BlockDuration time.Duration
}

// Listener implements a RakNet connection listener. It follows the same
// methods as those implemented by the TCPListener in the net package. Listener
// implements the net.Listener interface.
type Listener struct {
	conf    ListenConfig
	handler *listenerConnectionHandler
	sec     *security

	once   sync.Once
	closed chan struct{}

	conn net.PacketConn
	// conns holds the packet sockets used by the listener. conn always points to
	// the first entry.
	conns []net.PacketConn
	// incoming is a channel of incoming connections. Connections that end up in
	// here will also end up in the connections map.
	incoming chan *Conn

	// connections is a map of currently active connections, indexed by their
	// address.
	connections sync.Map

	// id is a random server ID generated upon starting listening. It is used
	// several times throughout the connection sequence of RakNet.
	id int64

	// pongData is a byte slice of data that is sent in an unconnected pong
	// packet each time the client sends and unconnected ping to the server.
	pongData atomic.Pointer[[]byte]
}

type listenerUnconnectedDatagram struct {
	addr net.Addr
	data []byte
}

// listenerID holds the next ID to use for a Listener.
var listenerID = rand.Int64()

// Listen listens on the address passed and returns a listener that may be used
// to accept connections. If not successful, an error is returned. The address
// follows the same rules as those defined in the net.TCPListen() function.
// Specific features of the listener may be modified once it is returned, such
// as the used log and/or the accepted protocol.
func (conf ListenConfig) Listen(address string) (*Listener, error) {
	if conf.ErrorLog == nil {
		conf.ErrorLog = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	conf.ErrorLog = conf.ErrorLog.With("src", "listener")

	if conf.BlockDuration == 0 {
		conf.BlockDuration = time.Second * 10
	}
	if conf.ReusePortSockets < 1 {
		conf.ReusePortSockets = 1
	}

	conns, err := conf.listenPacketConns("udp", address, conf.ReusePortSockets)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: "raknet", Source: nil, Addr: nil, Err: err}
	}
	listener := &Listener{
		conf:     conf,
		conn:     conns[0],
		conns:    conns,
		incoming: make(chan *Conn, 8),
		closed:   make(chan struct{}),
		id:       atomic.AddInt64(&listenerID, 1),
		sec:      newSecurity(conf),
	}

	listener.handler = &listenerConnectionHandler{
		listener: listener,
	}
	listener.pongData.Store(new([]byte))

	go listener.listen()
	go listener.updateConnections()
	go listener.sec.gc(listener.closed)
	go listener.handler.cleanup(listener.closed)
	return listener, nil
}

func (conf ListenConfig) listenPacketConns(network, address string, socketCount int) ([]net.PacketConn, error) {
	if socketCount < 1 {
		socketCount = 1
	}
	if conf.UpstreamPacketListener != nil {
		return openPacketConns(socketCount, address, func(bindAddress string) (net.PacketConn, error) {
			return conf.UpstreamPacketListener.ListenPacket(network, bindAddress)
		})
	}
	return listenPacketConnsDefault(network, address, socketCount)
}

func openPacketConns(socketCount int, address string, listen func(address string) (net.PacketConn, error)) ([]net.PacketConn, error) {
	conns := make([]net.PacketConn, 0, socketCount)
	bindAddress := address
	for i := 0; i < socketCount; i++ {
		conn, err := listen(bindAddress)
		if err != nil {
			_ = closePacketConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
		if localAddr := conn.LocalAddr(); localAddr != nil {
			bindAddress = localAddr.String()
		}
	}
	return conns, nil
}

func closePacketConns(conns []net.PacketConn) error {
	var errs []error
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (listener *Listener) packetConns() []net.PacketConn {
	if len(listener.conns) != 0 {
		return listener.conns
	}
	if listener.conn != nil {
		return []net.PacketConn{listener.conn}
	}
	return nil
}

// Listen listens on the address passed and returns a listener that may be used
// to accept connections. If not successful, an error is returned. The address
// follows the same rules as those defined in the net.TCPListen() function.
// Specific features of the listener may be modified once it is returned, such
// as the used log and/or the accepted protocol.
func Listen(address string) (*Listener, error) {
	var lc ListenConfig
	return lc.Listen(address)
}

// Accept blocks until a connection can be accepted by the listener. If
// successful, Accept returns a connection that is ready to send and receive
// data. If not successful, a nil listener is returned and an error describing
// the problem.
func (listener *Listener) Accept() (net.Conn, error) {
	conn, ok := <-listener.incoming
	if !ok {
		return nil, &net.OpError{Op: "accept", Net: "raknet", Source: nil, Addr: nil, Err: ErrListenerClosed}
	}
	return conn, nil
}

// Addr returns the address the Listener is bound to and listening for
// connections on.
func (listener *Listener) Addr() net.Addr {
	return listener.conn.LocalAddr()
}

// Close closes the listener so that it may be cleaned up. It makes sure the
// goroutine handling incoming packets is able to be freed.
func (listener *Listener) Close() error {
	var err error
	listener.once.Do(func() {
		close(listener.closed)
		err = closePacketConns(listener.packetConns())
	})
	return err
}

// PongData sets the pong data that is used to respond with when a client sends
// a ping. It usually holds game specific data that is used to display in a
// server list. If a data slice is set with a size bigger than math.MaxInt16,
// the function panics.
func (listener *Listener) PongData(data []byte) {
	if len(data) > math.MaxInt16 {
		panic(fmt.Sprintf("pong data: must be no longer than %v bytes, got %v", math.MaxInt16, len(data)))
	}
	listener.pongData.Store(&data)
}

// ID returns the unique ID of the listener. This ID is usually used by a
// client to identify a specific server during a single session.
func (listener *Listener) ID() int64 {
	return listener.id
}

const (
	connectionSequenceTimeout          = 10 * time.Second
	listenerUnconnectedDatagramWorkers = 4
	listenerUnconnectedDatagramBuffer  = 4096
)

// updateConnections deletes all connections that have failed to pass the pre-connection sequence and
// have been in the connections map for more than 30 seconds. It also updates connections that
// recently just completed the full connection sequence.
func (listener *Listener) updateConnections() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			listener.connections.Range(func(key, value any) bool {
				conn := value.(*Conn)
				select {
				case <-listener.closed:
					return true
				case <-conn.connected:
					// OK: The connection has already completed the connection sequence.
					if conn.accepted.CompareAndSwap(false, true) {
						listener.incoming <- conn
					}
				default:
					if time.Since(conn.createdAt) > connectionSequenceTimeout {
						conn.closeImmediately()
						listener.connections.Delete(key)
						listener.handler.log().Debug("connection failed to complete connection sequence in time", "raddr", conn.raddr.String())
					}
				}
				return true
			})
		case <-listener.closed:
			return
		}
	}
}

// listen continuously reads from the listener's UDP connection, until closed
// has a value in it.
func (listener *Listener) listen() {
	conns := listener.packetConns()
	if len(conns) == 0 {
		close(listener.incoming)
		return
	}

	unconnectedDatagrams := make(chan listenerUnconnectedDatagram, listenerUnconnectedDatagramBuffer)
	defer close(unconnectedDatagrams)

	listener.startUnconnectedDatagramWorkers(unconnectedDatagrams)

	var wg sync.WaitGroup
	for _, conn := range conns {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			listener.listenConn(conn, unconnectedDatagrams)
		}()
	}
	wg.Wait()
	close(listener.incoming)
}

func (listener *Listener) listenConn(conn net.PacketConn, unconnectedDatagrams chan<- listenerUnconnectedDatagram) {
	if listener.listenOptimized(conn, unconnectedDatagrams) {
		return
	}
	listener.listenReadFrom(conn, unconnectedDatagrams)
}

// listenReadFrom continuously reads from the listener's UDP connection using
// net.PacketConn.ReadFrom, until closed has a value in it.
func (listener *Listener) listenReadFrom(conn net.PacketConn, unconnectedDatagrams chan<- listenerUnconnectedDatagram) {
	// Create a buffer with the maximum size a UDP packet sent over RakNet is
	// allowed to have. We can re-use this buffer for each packet.
	b := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(b)
		addrStr := "unknown"
		if addr != nil {
			addrStr = addr.String()
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			listener.conf.ErrorLog.Error("read from: "+err.Error(), "raddr", addrStr)
			continue
		} else if n == 0 {
			continue
		}
		listener.dispatchDatagram(b[:n], addr, unconnectedDatagrams)
	}
}

func (listener *Listener) startUnconnectedDatagramWorkers(unconnectedDatagrams <-chan listenerUnconnectedDatagram) {
	for i := 0; i < listenerUnconnectedDatagramWorkers; i++ {
		go func() {
			for {
				select {
				case <-listener.closed:
					return
				case datagram, ok := <-unconnectedDatagrams:
					if !ok {
						return
					}
					listener.handleUnconnectedDatagram(datagram)
				}
			}
		}()
	}
}

func (listener *Listener) dispatchDatagram(b []byte, addr net.Addr, unconnectedDatagrams chan<- listenerUnconnectedDatagram) {
	if len(b) == 0 || listener.sec.blocked(addr) {
		return
	}

	payload := make([]byte, len(b))
	copy(payload, b)

	if b[0]&bitFlagDatagram != 0 || b[0] == message.IDDisconnectNotification {
		if value, found := listener.connections.Load(resolve(addr)); found {
			value.(*Conn).queueIncomingDatagram(payload)
		}
		return
	}

	// Avoid unbounded unconnected backlog under packet floods by dropping when
	// the worker queue is saturated.
	select {
	case <-listener.closed:
		return
	case unconnectedDatagrams <- listenerUnconnectedDatagram{addr: addr, data: payload}:
	default:
	}
}

func (listener *Listener) handleUnconnectedDatagram(datagram listenerUnconnectedDatagram) {
	if err := listener.handler.handleUnconnected(datagram.data, datagram.addr); err != nil && !errors.Is(err, net.ErrClosed) {
		addrStr := "unknown"
		if datagram.addr != nil {
			addrStr = datagram.addr.String()
			listener.sec.block(datagram.addr)
		}
		listener.conf.ErrorLog.Error("handle packet: "+err.Error(), "raddr", addrStr, "block-duration", max(0, listener.conf.BlockDuration))
	}
}

// security implements security measurements against DoS attacks against a
// Listener.
type security struct {
	conf ListenConfig

	blockCount atomic.Uint32

	mu     sync.Mutex
	blocks map[[16]byte]time.Time
}

// newSecurity uses settings from a ListenConfig to create a security.
func newSecurity(conf ListenConfig) *security {
	return &security{conf: conf, blocks: make(map[[16]byte]time.Time)}
}

// gc clears garbage from the security layer every second until the stop channel
// passed is closed.
func (s *security) gc(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.gcBlocks()
		case <-stop:
			return
		}
	}
}

// block stops the handling of packets originating from the IP of a net.Addr.
func (s *security) block(addr net.Addr) {
	if s.conf.BlockDuration < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blockCount.Add(1)
	s.blocks[[16]byte(addr.(*net.UDPAddr).IP.To16())] = time.Now()
}

// blocked checks if the IP of a net.Addr is currently blocked from any packet
// handling.
func (s *security) blocked(addr net.Addr) bool {
	if s.conf.BlockDuration < 0 || s.blockCount.Load() == 0 {
		// Fast path optimisation: Prevents (relatively costly) map lookups.
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, blocked := s.blocks[[16]byte(addr.(*net.UDPAddr).IP.To16())]
	return blocked
}

// gcBlocks removes blocks from the map that are no longer active. gcBlocks only
// attempts to clear outdated blocks if there are two times more blocks active
// than there were after the previous call to gcBlocks.
func (s *security) gcBlocks() {
	if s.blockCount.Load() == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	maps.DeleteFunc(s.blocks, func(ip [16]byte, t time.Time) bool {
		return now.Sub(t) > s.conf.BlockDuration
	})
	s.blockCount.Store(uint32(len(s.blocks)))
}
