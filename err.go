package raknet

import (
	"errors"
	"net"
	"strings"
)

var (
	// ErrBufferTooSmall is returned when Conn.Read is called with a byte slice
	// that is too small to contain the packet to be read.
	ErrBufferTooSmall = errors.New("a message sent was larger than the buffer used to receive the message into")
	// ErrListenerClosed is returned when Listener.Accept is called on a closed
	// listener.
	ErrListenerClosed = errors.New("use of closed listener")
	// ErrNotSupported is returned for deadline methods of a Conn, which are not
	// supported on a raknet.Conn.
	ErrNotSupported = errors.New("feature not supported")
)

// ErrConnectionClosed checks if the error passed was an error caused by reading from a Conn of which the
// connection was closed.
func ErrConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), net.ErrClosed.Error())
}

// error wraps the error passed into a net.OpError with the op as operation and
// returns it, or nil if the error passed is nil.
func (conn *Conn) error(err error, op string) error {
	if err == nil {
		return nil
	}
	return &net.OpError{
		Op:     op,
		Net:    "raknet",
		Source: conn.LocalAddr(),
		Addr:   conn.raddr,
		Err:    err,
	}
}
