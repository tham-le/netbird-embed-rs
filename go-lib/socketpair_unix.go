//go:build !windows

package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// openNoFollow makes capture files fail instead of following a planted
// symlink.
const openNoFollow = unix.O_NOFOLLOW

// createSocketPair creates a Unix socketpair and returns the two FDs. Both
// ends are close-on-exec so an exec'd child cannot inherit live mesh sockets;
// Rust receives an already-CLOEXEC FD.
func createSocketPair() ([2]int, error) {
	return socketPair(unix.SOCK_STREAM)
}

// createDatagramSocketPair creates a SOCK_DGRAM Unix socketpair that preserves
// message boundaries for UDP datagram forwarding.
func createDatagramSocketPair() ([2]int, error) {
	return socketPair(unix.SOCK_DGRAM)
}

func socketPair(typ int) ([2]int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, typ, 0)
	if err != nil {
		return [2]int{-1, -1}, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return fds, nil
}

// pumpConnection bidirectionally copies data between a net.Conn and a socketpair FD.
// Closes both when either side is done.
func pumpConnection(conn net.Conn, fd int) {
	file := os.NewFile(uintptr(fd), "socketpair")
	defer file.Close()
	defer conn.Close()

	fileConn, err := net.FileConn(file)
	if err != nil {
		return
	}
	defer fileConn.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(fileConn, conn)
		close(done)
	}()
	io.Copy(conn, fileConn)
	<-done
}

// pumpDatagrams bidirectionally copies datagrams between a net.PacketConn
// and a SOCK_DGRAM socketpair FD.
//
// A single socketpair cannot carry peer addresses, so outbound datagrams go to
// the peer that was active most recently. Reverse proxies use per-peer local
// sockets instead and demultiplex properly.
func pumpDatagrams(meshConn net.PacketConn, fd int) {
	file := os.NewFile(uintptr(fd), "dgram-socketpair")
	defer file.Close()
	defer meshConn.Close()

	var lastAddr atomic.Pointer[net.Addr]

	// mesh -> socketpair
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := meshConn.ReadFrom(buf)
			if err != nil {
				return
			}
			lastAddr.Store(&addr)
			if _, err := file.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// socketpair -> mesh
	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if err != nil {
			return
		}
		if addr := lastAddr.Load(); addr != nil {
			_, _ = meshConn.WriteTo(buf[:n], *addr)
		}
	}
}

// pumpDatagramsConn forwards datagrams to and from a connected UDP net.Conn
// (the result of dialing UDP through the mesh).
func pumpDatagramsConn(conn net.Conn, fd int) {
	file := os.NewFile(uintptr(fd), "dgram-socketpair")
	defer file.Close()
	defer conn.Close()

	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := file.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if err != nil {
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
	}
}

// acceptLoop accepts connections from a listener and pumps each through a socketpair.
// For each accepted connection, it writes the client-side FD as a 4-byte little-endian
// integer over the signaling socket. The Rust side reads these integers to obtain FDs.
func acceptLoop(listener net.Listener, sigFd int) {
	defer listener.Close()
	sigFile := os.NewFile(uintptr(sigFd), "signal-sock")
	defer sigFile.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		if !acceptSem.acquire() {
			_ = conn.Close()
			continue
		}

		go func() {
			defer acceptSem.release()
			fds, err := createSocketPair()
			if err != nil {
				_ = conn.Close()
				return
			}

			// Write the client FD as a 4-byte LE integer over the signaling socket.
			var fdBuf [4]byte
			binary.LittleEndian.PutUint32(fdBuf[:], uint32(fds[1]))
			if _, err := sigFile.Write(fdBuf[:]); err != nil {
				// Nobody will ever receive this FD again.
				unix.Close(fds[1])
				unix.Close(fds[0])
				_ = conn.Close()
				return
			}

			// Blocks until the connection ends; the semaphore stays held so a
			// burst cannot accumulate unbounded pumps.
			pumpConnection(conn, fds[0])
		}()
	}
}
