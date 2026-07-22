package raknet

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRegisterConnectionKeepsConnectionsToSameRemote(t *testing.T) {
	first := tickerTestConn(t, 19132)
	second := tickerTestConn(t, 19132)

	registerConnection(first)
	registerConnection(second)

	activeConnectionsMu.Lock()
	defer activeConnectionsMu.Unlock()
	if len(activeConnections) != 2 {
		t.Fatalf("active connection count = %d, want 2", len(activeConnections))
	}
}

func TestUnregisterConnectionRemovesOnlyTargetConnection(t *testing.T) {
	first := tickerTestConn(t, 19133)
	second := tickerTestConn(t, 19133)

	registerConnection(first)
	registerConnection(second)
	unregisterTickedConnection(first)

	activeConnectionsMu.Lock()
	defer activeConnectionsMu.Unlock()
	if len(activeConnections) != 1 {
		t.Fatalf("active connection count = %d, want 1", len(activeConnections))
	}
}

func tickerTestConn(t *testing.T, port int) *Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	conn := &Conn{
		raddr:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port},
		ctx:    ctx,
		ticker: make(chan time.Time, 1),
	}
	t.Cleanup(func() {
		cancel()
		unregisterTickedConnection(conn)
	})
	return conn
}
