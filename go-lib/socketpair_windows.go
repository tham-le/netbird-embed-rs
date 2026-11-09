//go:build windows

package main

import (
	"errors"
	"net"
)

var errNotSupported = errors.New("socketpair not supported on Windows")

// openNoFollow is not available on Windows; os.OpenFile still creates the
// file with the requested mode.
const openNoFollow = 0

func createSocketPair() ([2]int, error) {
	return [2]int{-1, -1}, errNotSupported
}

func createDatagramSocketPair() ([2]int, error) {
	return [2]int{-1, -1}, errNotSupported
}

func pumpConnection(conn net.Conn, fd int) {
	conn.Close()
}

func pumpDatagrams(meshConn net.PacketConn, fd int) {
	meshConn.Close()
}

func pumpDatagramsConn(conn net.Conn, fd int) {
	conn.Close()
}

func acceptLoop(listener net.Listener, sigFd int) {
	listener.Close()
}
