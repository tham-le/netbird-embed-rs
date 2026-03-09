package main

/*
#include <stdlib.h>
#include <string.h>
#include <errno.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	"github.com/netbirdio/netbird/client/embed"
)

var (
	handleMu      sync.Mutex
	clients       = make(map[C.int]*clientState)
	nextID        C.int = 1
	lastCreateErr string
)

type clientState struct {
	mu      sync.Mutex
	client  *embed.Client
	cancel  context.CancelFunc
	lastErr string
}

func getClient(handle C.int) (*clientState, bool) {
	handleMu.Lock()
	defer handleMu.Unlock()
	cs, ok := clients[handle]
	return cs, ok
}

func setError(handle C.int, err error) C.int {
	if cs, ok := getClient(handle); ok {
		cs.mu.Lock()
		cs.lastErr = err.Error()
		cs.mu.Unlock()
	}
	return -1
}

func writeJSON(data []byte, buf *C.char, bufLen C.int) C.int {
	needed := len(data) + 1
	if int(bufLen) < needed {
		return C.int(C.ERANGE)
	}
	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(cData), C.size_t(needed))
	return 0
}

// nb_new creates a new NetBird embedded client.
// Returns a handle > 0 on success, or -1 on error.
// On failure, use nb_create_errmsg to retrieve the error.
//
//export nb_new
func nb_new(setup_key *C.char, management_url *C.char, device_name *C.char, token *C.char, wireguard_port C.int) C.int {
	opts := embed.Options{}

	if setup_key != nil {
		if sk := C.GoString(setup_key); sk != "" {
			opts.SetupKey = sk
		}
	}
	if management_url != nil {
		if mgmt := C.GoString(management_url); mgmt != "" {
			opts.ManagementURL = mgmt
		}
	}
	if device_name != nil {
		if dn := C.GoString(device_name); dn != "" {
			opts.DeviceName = dn
		}
	}
	if token != nil {
		if t := C.GoString(token); t != "" {
			opts.JWTToken = t
		}
	}

	if wireguard_port >= 0 {
		port := int(wireguard_port)
		opts.WireguardPort = &port
	}

	client, err := embed.New(opts)
	if err != nil {
		handleMu.Lock()
		lastCreateErr = err.Error()
		handleMu.Unlock()
		return -1
	}

	handleMu.Lock()
	defer handleMu.Unlock()
	handle := nextID
	nextID++
	clients[handle] = &clientState{client: client}
	return handle
}

// nb_create_errmsg writes the last nb_new error into the caller-provided buffer.
//
//export nb_create_errmsg
func nb_create_errmsg(buf *C.char, buf_len C.int) {
	handleMu.Lock()
	msg := lastCreateErr
	handleMu.Unlock()

	if msg == "" {
		msg = "no error"
	}
	writeCString(msg, buf, buf_len)
}

// nb_start starts the NetBird client (joins the mesh).
// Returns 0 on success, -1 on error.
//
//export nb_start
func nb_start(handle C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	cs.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cs.cancel = cancel
	cs.mu.Unlock()

	if err := cs.client.Start(ctx); err != nil {
		cs.mu.Lock()
		cs.cancel = nil
		cs.mu.Unlock()
		cancel()
		return setError(handle, err)
	}
	return 0
}

// nb_stop stops the NetBird client (leaves the mesh).
// Returns 0 on success, -1 on error.
//
//export nb_stop
func nb_stop(handle C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	cs.mu.Lock()
	cancel := cs.cancel
	cs.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if err := cs.client.Stop(context.Background()); err != nil {
		return setError(handle, err)
	}
	return 0
}

type StatusInfo struct {
	State           string     `json:"state"`
	IP              string     `json:"ip"`
	PubKey          string     `json:"pub_key"`
	FQDN            string     `json:"fqdn"`
	ManagementState string     `json:"management_state"`
	SignalState     string     `json:"signal_state"`
	Peers           []PeerInfo `json:"peers"`
	Error           string     `json:"error,omitempty"`
}

type PeerInfo struct {
	IP         string `json:"ip"`
	PubKey     string `json:"pub_key"`
	FQDN       string `json:"fqdn"`
	ConnStatus string `json:"conn_status"`
	Relayed    bool   `json:"relayed"`
	Latency    string `json:"latency"`
}

func connStatusStr(s embed.PeerConnStatus) string {
	if s == embed.PeerStatusConnected {
		return "connected"
	}
	return "disconnected"
}

// nb_status writes the client status as JSON into the caller-provided buffer.
// Returns 0 on success, ERANGE if buffer too small, -1 on error.
//
//export nb_status
func nb_status(handle C.int, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	fullStatus, err := cs.client.Status()
	if err != nil {
		return setError(handle, err)
	}

	peers := make([]PeerInfo, 0, len(fullStatus.Peers))
	for _, p := range fullStatus.Peers {
		peers = append(peers, PeerInfo{
			IP:         p.IP,
			PubKey:     p.PubKey,
			FQDN:       p.FQDN,
			ConnStatus: connStatusStr(p.ConnStatus),
			Relayed:    p.Relayed,
			Latency:    p.Latency.String(),
		})
	}

	mgmtState := "disconnected"
	if fullStatus.ManagementState.Connected {
		mgmtState = "connected"
	}
	sigState := "disconnected"
	if fullStatus.SignalState.Connected {
		sigState = "connected"
	}

	info := StatusInfo{
		IP:              fullStatus.LocalPeerState.IP,
		PubKey:          fullStatus.LocalPeerState.PubKey,
		FQDN:            fullStatus.LocalPeerState.FQDN,
		ManagementState: mgmtState,
		SignalState:     sigState,
		Peers:           peers,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return setError(handle, err)
	}

	return writeJSON(data, buf, buf_len)
}

// nb_peers writes just the peer list as JSON into the caller-provided buffer.
// Returns 0 on success, ERANGE if buffer too small, -1 on error.
//
//export nb_peers
func nb_peers(handle C.int, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	fullStatus, err := cs.client.Status()
	if err != nil {
		return setError(handle, err)
	}

	peers := make([]PeerInfo, 0, len(fullStatus.Peers))
	for _, p := range fullStatus.Peers {
		peers = append(peers, PeerInfo{
			IP:         p.IP,
			PubKey:     p.PubKey,
			FQDN:       p.FQDN,
			ConnStatus: connStatusStr(p.ConnStatus),
			Relayed:    p.Relayed,
			Latency:    p.Latency.String(),
		})
	}

	data, err := json.Marshal(peers)
	if err != nil {
		return setError(handle, err)
	}

	return writeJSON(data, buf, buf_len)
}

// nb_dial dials a peer address over the mesh network.
// Returns a file descriptor on success, -1 on error.
//
//export nb_dial
func nb_dial(handle C.int, net_type *C.char, addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	goNet := C.GoString(net_type)
	goAddr := C.GoString(addr)

	if goNet != "tcp" && goNet != "udp" {
		return setError(handle, fmt.Errorf("unsupported network type: %q", goNet))
	}

	conn, err := cs.client.DialContext(context.Background(), goNet, goAddr)
	if err != nil {
		return setError(handle, err)
	}

	fds, err := createSocketPair()
	if err != nil {
		conn.Close()
		return setError(handle, err)
	}

	go pumpConnection(conn, fds[0])

	return C.int(fds[1])
}

// nb_listen starts listening on a mesh address.
// Returns a file descriptor on success, -1 on error.
// Each accepted connection is pumped through a socketpair; the client FD
// is written as a 4-byte little-endian int over the signaling socket.
//
//export nb_listen
func nb_listen(handle C.int, net_type *C.char, addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}

	goNet := C.GoString(net_type)
	goAddr := C.GoString(addr)

	if goNet != "tcp" {
		return setError(handle, fmt.Errorf("unsupported network type: %q", goNet))
	}

	listener, err := cs.client.ListenTCP(goAddr)
	if err != nil {
		return setError(handle, err)
	}

	fds, err := createSocketPair()
	if err != nil {
		listener.Close()
		return setError(handle, err)
	}

	go acceptLoop(listener, fds[0])

	return C.int(fds[1])
}

// nb_errmsg writes the last error message into the caller-provided buffer.
//
//export nb_errmsg
func nb_errmsg(handle C.int, buf *C.char, buf_len C.int) {
	cs, ok := getClient(handle)
	if !ok {
		return
	}

	cs.mu.Lock()
	msg := cs.lastErr
	cs.mu.Unlock()

	if msg == "" {
		msg = "no error"
	}
	writeCString(msg, buf, buf_len)
}

func writeCString(msg string, buf *C.char, bufLen C.int) {
	needed := len(msg) + 1
	if int(bufLen) < needed {
		needed = int(bufLen)
		msg = msg[:needed-1]
	}

	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(cMsg), C.size_t(needed))
}

// nb_free destroys the client and releases all resources.
//
//export nb_free
func nb_free(handle C.int) {
	handleMu.Lock()
	cs, ok := clients[handle]
	if ok {
		delete(clients, handle)
	}
	handleMu.Unlock()

	if ok {
		cs.mu.Lock()
		cancel := cs.cancel
		cs.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		cs.client.Stop(context.Background())
	}
}

func main() {}
