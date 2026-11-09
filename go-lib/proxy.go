package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// proxyDialTimeout bounds every TCP/UDP dial through the mesh or to a
	// local target, so one unreachable peer cannot pin a goroutine forever.
	proxyDialTimeout = 15 * time.Second
	// proxyIdleTimeout closes a relayed TCP connection that carries no data
	// in either direction for this long.
	proxyIdleTimeout = 5 * time.Minute
	// maxProxyConns caps concurrent relayed connections per client.
	maxProxyConns = 512
	// maxUDPPeers caps the per-peer UDP sessions of one reverse proxy.
	maxUDPPeers = 256
	// udpPeerIdle expires a reverse-proxy UDP peer that never answers.
	udpPeerIdle = 2 * time.Minute
)

// acquireConn reserves a relay slot. It never blocks: a connection that
// arrives while the proxy is saturated is closed immediately.
func (cs *clientState) acquireConn() bool {
	select {
	case cs.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (cs *clientState) releaseConn() {
	<-cs.connSem
}

// dialMesh dials through the mesh netstack with a bounded context.
func (cs *clientState) dialMesh(network, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(cs.ctx, proxyDialTimeout)
	defer cancel()
	return cs.client.DialContext(ctx, network, target)
}

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
	cs.clearError()

	target := cStringOrEmpty(target_addr)
	if target == "" {
		return setError(handle, fmt.Errorf("proxy target is required"))
	}

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
		if !cs.acquireConn() {
			_ = conn.Close()
			continue
		}
		go func() {
			defer cs.releaseConn()
			proxyTCPConn(cs, conn, target)
		}()
	}
}

func proxyTCPConn(cs *clientState, local net.Conn, target string) {
	defer local.Close()

	mesh, err := cs.dialMesh("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: proxy dial %s failed: %v\n", target, err)
		return
	}
	defer mesh.Close()

	relay(local, mesh)
}

// relay copies both directions with an idle deadline and half-closes the
// write side so the peer observes EOF.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(proxyIdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(proxyIdleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}

	go cp(a, b)
	cp(b, a)
	wg.Wait()
}

// proxyUDPForwardLoop forwards UDP datagrams between a local PacketConn
// and a single mesh UDP connection. Datagram boundaries are preserved
// because both sides use Read/Write (not io.Copy over streams).
func proxyUDPForwardLoop(cs *clientState, local net.PacketConn, target string) {
	defer local.Close()

	mesh, err := cs.dialMesh("udp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: proxy dial udp %s failed: %v\n", target, err)
		return
	}
	defer mesh.Close()

	// Track the local client address so we can send replies back.
	var clientAddr atomic.Pointer[net.Addr]

	// local -> mesh
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			clientAddr.Store(&addr)
			if _, err := mesh.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// mesh -> local
	buf := make([]byte, 65536)
	for {
		n, err := mesh.Read(buf)
		if err != nil {
			return
		}
		if addr := clientAddr.Load(); addr != nil {
			_, _ = local.WriteTo(buf[:n], *addr)
		}
	}
}

// nb_reverse_proxy listens on a port inside the mesh netstack and forwards
// incoming connections to a local address (e.g. localhost:8080).
//
// This is the mirror of nb_proxy: mesh peers connect to the overlay IP on
// mesh_port, and traffic is relayed to local_addr on the OS network stack.
//
// Returns the bound mesh port (>0) on success, -1 on error. Passing 0 asks
// the netstack for a random port; the chosen port is returned.
//
//export nb_reverse_proxy
func nb_reverse_proxy(handle C.int, mesh_port C.int, local_addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	localTarget := cStringOrEmpty(local_addr)
	if localTarget == "" {
		return setError(handle, fmt.Errorf("reverse proxy local address is required"))
	}
	if mesh_port < 0 || mesh_port > 65535 {
		return setError(handle, fmt.Errorf("reverse proxy port %d out of range", int(mesh_port)))
	}
	listenAddr := fmt.Sprintf(":%d", int(mesh_port))

	// TCP listener inside the mesh netstack
	tcpLn, err := cs.client.ListenTCP(listenAddr)
	if err != nil {
		return setError(handle, fmt.Errorf("reverse proxy tcp listen: %w", err))
	}
	boundPort := listenPort(tcpLn.Addr(), int(mesh_port))

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

	if !cs.acquireConn() {
		tcpLn.Close()
		udpConn.Close()
		return setError(handle, fmt.Errorf("reverse proxy connection limit reached"))
	}
	go func() {
		defer cs.releaseConn()
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			if !cs.acquireConn() {
				_ = conn.Close()
				continue
			}
			go func() {
				defer cs.releaseConn()
				reverseProxyTCPConn(conn, localTarget)
			}()
		}
	}()

	go reverseProxyUDPForwardLoop(udpConn, localTarget)

	return C.int(boundPort)
}

// listenPort extracts the port from a listener address, falling back to the
// requested port when the address family does not expose one.
func listenPort(addr net.Addr, requested int) int {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.Port > 0 {
		return tcpAddr.Port
	}
	if host, port, err := net.SplitHostPort(addr.String()); err == nil && host != "" {
		if p, err := net.LookupPort("tcp", port); err == nil && p > 0 {
			return p
		}
	}
	return requested
}

func reverseProxyTCPConn(mesh net.Conn, localTarget string) {
	defer mesh.Close()

	local, err := net.DialTimeout("tcp", localTarget, proxyDialTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: reverse proxy dial %s failed: %v\n", localTarget, err)
		return
	}
	defer local.Close()

	relay(mesh, local)
}

// udpPeer is one mesh peer with its own connected local socket, so replies
// from the local service go back to the peer that sent the request instead of
// the most recent sender.
type udpPeer struct {
	conn *net.UDPConn
	last atomic.Int64
}

// reverseProxyUDPForwardLoop demultiplexes mesh peers onto individual local
// UDP sockets and expires idle ones.
func reverseProxyUDPForwardLoop(meshConn net.PacketConn, localTarget string) {
	defer meshConn.Close()

	localAddr, err := net.ResolveUDPAddr("udp", localTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kyvpn: reverse proxy resolve %s failed: %v\n", localTarget, err)
		return
	}

	peers := make(map[string]*udpPeer)
	var mu sync.Mutex

	dropPeer := func(key string, p *udpPeer) {
		mu.Lock()
		if peers[key] == p {
			delete(peers, key)
		}
		mu.Unlock()
		_ = p.conn.Close()
	}

	getPeer := func(addr net.Addr) *udpPeer {
		key := addr.String()
		mu.Lock()
		if p := peers[key]; p != nil {
			p.last.Store(time.Now().UnixNano())
			mu.Unlock()
			return p
		}
		if len(peers) >= maxUDPPeers {
			mu.Unlock()
			return nil
		}
		conn, err := net.DialUDP("udp", nil, localAddr)
		if err != nil {
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "kyvpn: reverse proxy udp dial %s failed: %v\n", localTarget, err)
			return nil
		}
		p := &udpPeer{conn: conn}
		p.last.Store(time.Now().UnixNano())
		peers[key] = p
		mu.Unlock()

		go func() {
			buf := make([]byte, 65536)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(udpPeerIdle))
				n, err := conn.Read(buf)
				if err != nil {
					dropPeer(key, p)
					return
				}
				p.last.Store(time.Now().UnixNano())
				_, _ = meshConn.WriteTo(buf[:n], addr)
			}
		}()
		return p
	}

	// Expire peers that stopped answering.
	stopJanitor := make(chan struct{})
	defer close(stopJanitor)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopJanitor:
				return
			case now := <-ticker.C:
				cutoff := now.Add(-udpPeerIdle).UnixNano()
				mu.Lock()
				for key, p := range peers {
					if p.last.Load() < cutoff {
						delete(peers, key)
						_ = p.conn.Close()
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, addr, err := meshConn.ReadFrom(buf)
		if err != nil {
			break
		}
		if p := getPeer(addr); p != nil {
			_, _ = p.conn.Write(buf[:n])
		}
	}

	mu.Lock()
	for _, p := range peers {
		_ = p.conn.Close()
	}
	mu.Unlock()
}
