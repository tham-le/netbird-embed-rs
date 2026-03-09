//go:build !windows

package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// createSocketPair creates a Unix socketpair and returns the two FDs.
func createSocketPair() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return [2]int{-1, -1}, err
	}
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

// createDatagramSocketPair creates a SOCK_DGRAM Unix socketpair that preserves
// message boundaries for UDP datagram forwarding.
func createDatagramSocketPair() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return [2]int{-1, -1}, err
	}
	return fds, nil
}

// pumpDatagrams bidirectionally copies datagrams between a net.PacketConn
// and a SOCK_DGRAM socketpair FD. Tracks the last sender address so
// outbound datagrams from the Rust side are routed to the correct peer.
func pumpDatagrams(meshConn net.PacketConn, fd int) {
	file := os.NewFile(uintptr(fd), "dgram-socketpair")
	defer file.Close()
	defer meshConn.Close()

	var lastAddr net.Addr
	var mu sync.Mutex

	// mesh -> socketpair
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := meshConn.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			lastAddr = addr
			mu.Unlock()
			file.Write(buf[:n])
		}
	}()

	// socketpair -> mesh
	buf := make([]byte, 65536)
	for {
		n, err := file.Read(buf)
		if err != nil {
			return
		}
		mu.Lock()
		addr := lastAddr
		mu.Unlock()
		if addr != nil {
			meshConn.WriteTo(buf[:n], addr)
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

		fds, err := createSocketPair()
		if err != nil {
			conn.Close()
			continue
		}

		go pumpConnection(conn, fds[0])

		// Write the client FD as a 4-byte LE integer over the signaling socket
		var fdBuf [4]byte
		binary.LittleEndian.PutUint32(fdBuf[:], uint32(fds[1]))
		_, err = sigFile.Write(fdBuf[:])
		if err != nil {
			syscall.Close(fds[1])
			continue
		}
		// FD ownership stays with this process — Rust reads the integer and
		// uses it directly (both sides share the same process).
	}
}
