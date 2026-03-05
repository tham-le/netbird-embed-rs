package main

import (
	"io"
	"net"
	"os"
	"syscall"
)

// createSocketPair creates a Unix socketpair and returns the two FDs.
// The caller is responsible for closing both ends.
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

// acceptLoop accepts connections from a listener and pumps them through socketpairs.
// The accepted FDs are written to the signaling socket.
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

		// Send the client FD over the signaling socket using SCM_RIGHTS
		err = sendFd(sigFile, fds[1])
		syscall.Close(fds[1]) // We've sent it, close our copy
		if err != nil {
			conn.Close()
			continue
		}
	}
}

// sendFd sends a file descriptor over a Unix socket using SCM_RIGHTS.
func sendFd(sock *os.File, fd int) error {
	rights := syscall.UnixRights(fd)
	return syscall.Sendmsg(int(sock.Fd()), []byte{0}, rights, nil, 0)
}
