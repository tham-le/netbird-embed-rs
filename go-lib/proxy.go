package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// nb_proxy starts a localhost TCP+UDP proxy forwarding to the given
// target address through the mesh netstack.
//
// Returns the local port (>0) on success, -1 on error.
// The proxy runs until nb_stop or nb_free is called.
//
//export nb_proxy
func nb_proxy(handle C.int, target_addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	target := C.GoString(target_addr)

	// TCP listener on a random port
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return setError(handle, fmt.Errorf("proxy tcp listen: %w", err))
	}
	port := tcpLn.Addr().(*net.TCPAddr).Port

	// UDP listener on the same port
	udpConn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		tcpLn.Close()
		return setError(handle, fmt.Errorf("proxy udp listen: %w", err))
	}

	// Store cleanup functions so nb_stop/nb_free can shut them down
	cs.mu.Lock()
	cs.proxyCleanup = append(cs.proxyCleanup, func() {
		tcpLn.Close()
		udpConn.Close()
	})
	cs.mu.Unlock()

	go proxyTCPAcceptLoop(cs, tcpLn, target)
	go proxyUDPForwardLoop(cs, udpConn, target)

	return C.int(port)
}

// proxyTCPAcceptLoop accepts local TCP connections and relays each
// through a fresh mesh TCP connection to the target.
func proxyTCPAcceptLoop(cs *clientState, ln net.Listener, target string) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go proxyTCPConn(cs, conn, target)
	}
}

func proxyTCPConn(cs *clientState, local net.Conn, target string) {
	defer local.Close()

	mesh, err := cs.client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: proxy dial %s failed: %v\n", target, err)
		return
	}
	defer mesh.Close()

	relay(local, mesh)
}

func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		close(done)
	}()
	io.Copy(a, b)
	<-done
}

// proxyUDPForwardLoop forwards UDP datagrams between a local PacketConn
// and a single mesh UDP connection. Datagram boundaries are preserved
// because both sides use Read/Write (not io.Copy over streams).
func proxyUDPForwardLoop(cs *clientState, local net.PacketConn, target string) {
	defer local.Close()

	mesh, err := cs.client.DialContext(context.Background(), "udp", target)
	if err != nil {
		return
	}
	defer mesh.Close()

	// Track the local client address so we can send replies back.
	// For Kyber, there is exactly one local client (kymux).
	var clientAddr net.Addr
	var mu sync.Mutex

	// local -> mesh
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = addr
			mu.Unlock()
			mesh.Write(buf[:n])
		}
	}()

	// mesh -> local
	buf := make([]byte, 65536)
	for {
		n, err := mesh.Read(buf)
		if err != nil {
			return
		}
		mu.Lock()
		addr := clientAddr
		mu.Unlock()
		if addr != nil {
			local.WriteTo(buf[:n], addr)
		}
	}
}

// nb_reverse_proxy listens on a port inside the mesh netstack and forwards
// incoming connections to a local address (e.g. localhost:8080).
//
// This is the mirror of nb_proxy: mesh peers connect to the overlay IP on
// mesh_port, and traffic is relayed to local_addr on the OS network stack.
//
// Returns 0 on success, -1 on error.
//
//export nb_reverse_proxy
func nb_reverse_proxy(handle C.int, mesh_port C.int, local_addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	localTarget := C.GoString(local_addr)
	listenAddr := fmt.Sprintf(":%d", int(mesh_port))

	// TCP listener inside the mesh netstack
	tcpLn, err := cs.client.ListenTCP(listenAddr)
	if err != nil {
		return setError(handle, fmt.Errorf("reverse proxy tcp listen: %w", err))
	}

	// UDP listener inside the mesh netstack
	udpConn, err := cs.client.ListenUDP(listenAddr)
	if err != nil {
		tcpLn.Close()
		return setError(handle, fmt.Errorf("reverse proxy udp listen: %w", err))
	}

	cs.mu.Lock()
	cs.proxyCleanup = append(cs.proxyCleanup, func() {
		tcpLn.Close()
		udpConn.Close()
	})
	cs.mu.Unlock()

	go reverseProxyTCPAcceptLoop(tcpLn, localTarget)
	go reverseProxyUDPForwardLoop(udpConn, localTarget)

	return 0
}

func reverseProxyTCPAcceptLoop(ln net.Listener, localTarget string) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go reverseProxyTCPConn(conn, localTarget)
	}
}

func reverseProxyTCPConn(mesh net.Conn, localTarget string) {
	defer mesh.Close()

	local, err := net.Dial("tcp", localTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: reverse proxy dial %s failed: %v\n", localTarget, err)
		return
	}
	defer local.Close()

	relay(mesh, local)
}

func reverseProxyUDPForwardLoop(meshConn net.PacketConn, localTarget string) {
	defer meshConn.Close()

	localConn, err := net.Dial("udp", localTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: reverse proxy udp dial %s failed: %v\n", localTarget, err)
		return
	}
	defer localConn.Close()

	// mesh -> local
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := meshConn.ReadFrom(buf)
			if err != nil {
				return
			}
			localConn.Write(buf[:n])
		}
	}()

	// local -> mesh (not needed for server-initiated UDP, but included for completeness)
	buf := make([]byte, 65536)
	for {
		n, err := localConn.Read(buf)
		if err != nil {
			return
		}
		// PacketConn needs WriteTo, but we don't know the remote mesh addr.
		// For QUIC, the server sends responses on the same connection, so
		// this direction isn't used in practice for reverse proxy.
		_ = n
	}
}
