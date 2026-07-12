//go:build linux

package raknet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	listenerBatchSize         = 1024
	listenerDatagramMaxLength = 1500
)

type linuxMMsgHdr struct {
	Hdr syscall.Msghdr
	Len uint32
}

type syscallPacketConn interface {
	SyscallConn() (syscall.RawConn, error)
}

type linuxPacketBatchReader struct {
	raw syscall.RawConn

	buffers [listenerBatchSize][listenerDatagramMaxLength]byte
	names   [listenerBatchSize]syscall.RawSockaddrAny
	iovecs  [listenerBatchSize]syscall.Iovec
	msgs    [listenerBatchSize]linuxMMsgHdr
}

func (listener *Listener) listenOptimized(conn net.PacketConn, unconnectedDatagrams chan<- listenerUnconnectedDatagram) bool {
	reader, err := newLinuxPacketBatchReader(conn)
	if err != nil {
		listener.conf.ErrorLog.Debug("linux batch socket read unavailable", "err", err)
		return false
	}

	for {
		n, err := reader.readBatch()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return true
			}
			listener.conf.ErrorLog.Error("read batch: "+err.Error(), "raddr", "unknown")
			continue
		}

		for i := range n {
			b, addr, ok := reader.packet(i)
			if !ok {
				continue
			}
			listener.dispatchDatagram(b, addr, unconnectedDatagrams)
		}
	}
}

func newLinuxPacketBatchReader(conn net.PacketConn) (*linuxPacketBatchReader, error) {
	sysConn, ok := conn.(syscallPacketConn)
	if !ok {
		return nil, fmt.Errorf("packet conn %T does not expose SyscallConn", conn)
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	reader := &linuxPacketBatchReader{raw: rawConn}
	for i := range reader.msgs {
		reader.iovecs[i].Base = &reader.buffers[i][0]
		reader.iovecs[i].SetLen(listenerDatagramMaxLength)
		reader.msgs[i].Hdr.Iov = &reader.iovecs[i]
		reader.msgs[i].Hdr.Iovlen = 1
		reader.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&reader.names[i]))
		reader.msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(reader.names[i]))
	}

	// Ensure the socket is configured non-blocking before using recvmmsg.
	var controlErr error
	if err = rawConn.Control(func(fd uintptr) {
		controlErr = syscall.SetNonblock(int(fd), true)
	}); err != nil {
		return nil, err
	}
	if controlErr != nil {
		return nil, controlErr
	}
	return reader, nil
}

func (reader *linuxPacketBatchReader) readBatch() (int, error) {
	for i := range reader.msgs {
		reader.msgs[i].Len = 0
		reader.msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(reader.names[i]))
	}

	var (
		n       int
		recvErr error
	)
	err := reader.raw.Read(func(fd uintptr) bool {
		for {
			n, recvErr = recvmmsg(int(fd), reader.msgs[:], syscall.MSG_DONTWAIT)
			switch recvErr {
			case nil:
				return true
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false
			default:
				return true
			}
		}
	})
	if err != nil {
		return 0, err
	}
	if recvErr == nil {
		return n, nil
	}
	if errors.Is(recvErr, syscall.EBADF) || errors.Is(recvErr, syscall.ENOTSOCK) {
		return 0, net.ErrClosed
	}
	return 0, os.NewSyscallError("recvmmsg", recvErr)
}

func (reader *linuxPacketBatchReader) packet(index int) ([]byte, *net.UDPAddr, bool) {
	packetLength := int(reader.msgs[index].Len)
	if packetLength < 0 {
		return nil, nil, false
	}
	if packetLength > len(reader.buffers[index]) {
		packetLength = len(reader.buffers[index])
	}
	addr, ok := rawSockaddrToUDPAddr(&reader.names[index], reader.msgs[index].Hdr.Namelen)
	if !ok {
		return nil, nil, false
	}
	return reader.buffers[index][:packetLength], addr, true
}

func rawSockaddrToUDPAddr(raw *syscall.RawSockaddrAny, nameLen uint32) (*net.UDPAddr, bool) {
	if raw == nil || nameLen == 0 {
		return nil, false
	}
	switch raw.Addr.Family {
	case syscall.AF_INET:
		if nameLen < uint32(unsafe.Sizeof(syscall.RawSockaddrInet4{})) {
			return nil, false
		}
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
		return &net.UDPAddr{
			IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
			Port: networkToHostShort(sa.Port),
		}, true
	case syscall.AF_INET6:
		if nameLen < uint32(unsafe.Sizeof(syscall.RawSockaddrInet6{})) {
			return nil, false
		}
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
		ip := make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])

		udpAddr := &net.UDPAddr{
			IP:   ip,
			Port: networkToHostShort(sa.Port),
		}
		if sa.Scope_id != 0 {
			if iface, err := net.InterfaceByIndex(int(sa.Scope_id)); err == nil {
				udpAddr.Zone = iface.Name
			}
		}
		return udpAddr, true
	default:
		return nil, false
	}
}

func recvmmsg(fd int, msgs []linuxMMsgHdr, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, errno := syscall.Syscall6(
		syscall.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		uintptr(flags),
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func networkToHostShort(v uint16) int {
	return int(v>>8) | int(v&0xff)<<8
}
