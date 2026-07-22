package raknet

import (
	"sync"
	"time"
)

var (
	activeConnections   = make(map[*Conn]struct{})
	activeConnectionsMu sync.Mutex
)

func init() {
	go tickConnections()
}

func tickConnections() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	unregisterQueue := make([]*Conn, 0, 64)
	for t := range ticker.C {
		activeConnectionsMu.Lock()
		for conn := range activeConnections {
			select {
			case <-conn.ctx.Done():
				// Connection was closed, queue it for unregistration.
				unregisterQueue = append(unregisterQueue, conn)
			default:
				select {
				case conn.ticker <- t:
					// OK.
				default:
					// Connection is busy and still hasn't processed the previous tick we sent it - skip for now.
				}
			}
		}
		activeConnectionsMu.Unlock()

		for _, conn := range unregisterQueue {
			unregisterTickedConnection(conn)
		}
		unregisterQueue = unregisterQueue[:0]
	}
}

func registerConnection(conn *Conn) {
	activeConnectionsMu.Lock()
	defer activeConnectionsMu.Unlock()

	activeConnections[conn] = struct{}{}
}

func unregisterTickedConnection(conn *Conn) {
	activeConnectionsMu.Lock()
	defer activeConnectionsMu.Unlock()

	if _, ok := activeConnections[conn]; ok {
		delete(activeConnections, conn)
		close(conn.ticker)
	}
}
