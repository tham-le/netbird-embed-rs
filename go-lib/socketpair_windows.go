//go:build windows

package main

import (
	"errors"
	"net"
)

var errNotSupported = errors.New("socketpair not supported on Windows")

func createSocketPair() ([2]int, error) {
	return [2]int{-1, -1}, errNotSupported
}

func pumpConnection(conn net.Conn, fd int) {
	conn.Close()
}

func acceptLoop(listener net.Listener, sigFd int) {
	listener.Close()
}
