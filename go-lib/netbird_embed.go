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
	"io"
	"math"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

var (
	handleMu      sync.Mutex
	clients             = make(map[C.int]*clientState)
	nextID        C.int = 1
	lastCreateErr string
)

type clientState struct {
	mu           sync.Mutex
	client       *embed.Client
	ctx          context.Context
	cancel       context.CancelFunc
	lastErr      string
	proxyCleanup []func()
	setupKey     string
	jwtToken     string
	deviceName   string
	preallocSet  bool
	exposes      map[string]*exposeEntry
	captures     map[C.int]*captureEntry
	listeners    map[int]struct{}
	// connSem caps concurrent relayed connections; see proxy.go.
	connSem chan struct{}
	// captureMu serializes capture start/stop so an ERANGE retry or a
	// concurrent caller cannot detach a freshly started session.
	captureMu sync.Mutex
}

// allocHandle returns an unused positive handle, wrapping before C.int can
// overflow into the -1 error sentinel.
func allocHandle() C.int {
	for {
		handle := nextID
		nextID++
		if nextID <= 0 {
			nextID = 1
		}
		if handle <= 0 {
			continue
		}
		if _, used := clients[handle]; !used {
			return handle
		}
	}
}

func (cs *clientState) clearError() {
	cs.mu.Lock()
	cs.lastErr = ""
	cs.mu.Unlock()
}

// semaphore bounds parallel work without blocking.
type semaphore struct {
	ch chan struct{}
}

func newSemaphore(n int) *semaphore {
	return &semaphore{ch: make(chan struct{}, n)}
}

func (s *semaphore) acquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *semaphore) release() {
	<-s.ch
}

// acceptSem bounds the number of connections being handed to the caller in
// parallel, so a burst cannot create unbounded socketpairs.
var acceptSem = newSemaphore(maxProxyConns)

// listenerMu guards listenerClosers, keyed by the signaling FD handed to the
// caller.
var (
	listenerMu      sync.Mutex
	listenerClosers = make(map[int]func())
)

func registerListener(fd int, closeFn func()) {
	listenerMu.Lock()
	listenerClosers[fd] = closeFn
	listenerMu.Unlock()
}

// closeListener stops a mesh listener by its signaling FD. Unknown FDs are a
// no-op, so a stale Drop after nb_free is safe.
func closeListener(fd int) {
	listenerMu.Lock()
	closeFn, ok := listenerClosers[fd]
	if ok {
		delete(listenerClosers, fd)
	}
	listenerMu.Unlock()
	if ok {
		closeFn()
	}
}

const (
	// exposeTimeout bounds the management round-trip of one expose request.
	exposeTimeout = 30 * time.Second
	// stopTimeout bounds client shutdown so a wedged management server does
	// not hang the host thread forever.
	stopTimeout = 30 * time.Second
	// dialTimeout bounds a direct Client::dial through the mesh.
	dialTimeout = 15 * time.Second
)

type exposeEntry struct {
	session  *embed.ExposeSession
	cancel   context.CancelFunc
	done     chan struct{}
	callID   string
	response []byte
}

// addExpose registers an expose session under its domain.
func (cs *clientState) addExpose(domain string, e *exposeEntry) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.exposes == nil {
		cs.exposes = make(map[string]*exposeEntry)
	}
	if _, exists := cs.exposes[domain]; exists {
		return fmt.Errorf("expose session for %q already exists", domain)
	}
	cs.exposes[domain] = e
	return nil
}

// findExpose returns the cached response for a call id, if the session is
// still tracked. Call ids are generated per Rust call, so the ERANGE retry
// hits the cache while a genuine second call creates a new session.
func (cs *clientState) findExpose(callID string) []byte {
	if callID == "" {
		return nil
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, e := range cs.exposes {
		if e.callID == callID && e.response != nil {
			return e.response
		}
	}
	return nil
}

func (cs *clientState) removeExpose(domain string, e *exposeEntry) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.exposes[domain] == e {
		delete(cs.exposes, domain)
	}
}

// takeExposes removes and returns every tracked expose session.
func (cs *clientState) takeExposes() []*exposeEntry {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	entries := make([]*exposeEntry, 0, len(cs.exposes))
	for _, e := range cs.exposes {
		entries = append(entries, e)
	}
	cs.exposes = nil
	return entries
}

// stopExposes cancels every session and waits for its keep-alive goroutine to
// finish. Waiting is required so StopExpose completes before the client stops.
func stopExposes(entries []*exposeEntry) {
	for _, e := range entries {
		e.cancel()
	}
	for _, e := range entries {
		<-e.done
	}
}

// teardownExpose cancels a session that never entered the map and waits for its
// keep-alive goroutine, so StopExpose finishes before the client stops.
func teardownExpose(ctx context.Context, resp *embed.ExposeSession) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = resp.Wait(ctx)
	}()
	<-done
}

var captureIDCounter int

// allocCaptureID returns the next capture ID. Callers hold captureMu, which
// keeps the counter race-free; it wraps back to 1 before becoming negative.
func allocCaptureID() int {
	if captureIDCounter >= math.MaxInt32 {
		captureIDCounter = 1
		return captureIDCounter
	}
	captureIDCounter++
	return captureIDCounter
}

type captureOptions struct {
	PcapPath string `json:"pcap_path"`
	TextPath string `json:"text_path"`
	Filter   string `json:"filter"`
	Verbose  bool   `json:"verbose"`
	ASCII    bool   `json:"ascii"`
}

func parseCaptureOptions(raw string) (captureOptions, error) {
	var opts captureOptions
	if err := json.Unmarshal([]byte(raw), &opts); err != nil {
		return captureOptions{}, err
	}
	return opts, nil
}

type captureEntry struct {
	sess  *embed.CaptureSession
	files []*os.File
	id    C.int
}

// takeCaptures removes and returns every tracked capture session.
func (cs *clientState) takeCaptures() []*captureEntry {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	entries := make([]*captureEntry, 0, len(cs.captures))
	for _, e := range cs.captures {
		entries = append(entries, e)
	}
	cs.captures = nil
	return entries
}

// stopCaptures stops each capture, waits for its writer goroutine to flush, and
// closes the output files.
func stopCaptures(entries []*captureEntry) {
	for _, e := range entries {
		e.sess.Stop()
		<-e.sess.Done()
		for _, f := range e.files {
			_ = f.Close()
		}
	}
}

func preallocEnabled(v *uint32) bool {
	return v != nil && *v != 0
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
	if buf == nil || int(bufLen) < needed {
		return C.int(C.ERANGE)
	}
	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(cData), C.size_t(needed))
	return 0
}

func cStringOrEmpty(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

func parseJSONStringList(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func optBool(v int) *bool {
	if v < 0 {
		return nil
	}
	b := v != 0
	return &b
}

func optUint16(v int) (*uint16, error) {
	if v < 0 {
		return nil, nil
	}
	if v > 65535 {
		return nil, fmt.Errorf("value %d out of uint16 range", v)
	}
	u := uint16(v)
	return &u, nil
}

func optUint32(v int) (*uint32, error) {
	if v < 0 {
		return nil, nil
	}
	if int64(v) > int64(^uint32(0)) {
		return nil, fmt.Errorf("value %d out of uint32 range", v)
	}
	u := uint32(v)
	return &u, nil
}

type exposeRequest struct {
	NamePrefix string                   `json:"name_prefix"`
	Domain     string                   `json:"domain"`
	Port       uint16                   `json:"port"`
	Protocol   embed.ExposeProtocolType `json:"protocol"`
	Pin        string                   `json:"pin"`
	Password   string                   `json:"password"`
	UserGroups []string                 `json:"user_groups"`
	ListenPort uint16                   `json:"listen_port"`
	CallID     string                   `json:"call_id"`
}

func parseExposeRequest(raw string) (exposeRequest, error) {
	var wire struct {
		NamePrefix string   `json:"name_prefix"`
		Domain     string   `json:"domain"`
		Port       uint16   `json:"port"`
		Protocol   string   `json:"protocol"`
		Pin        string   `json:"pin"`
		Password   string   `json:"password"`
		UserGroups []string `json:"user_groups"`
		ListenPort uint16   `json:"listen_port"`
		CallID     string   `json:"call_id"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return exposeRequest{}, err
	}
	protocol, err := exposeProtocol(wire.Protocol)
	if err != nil {
		return exposeRequest{}, err
	}
	return exposeRequest{
		NamePrefix: wire.NamePrefix,
		Domain:     wire.Domain,
		Port:       wire.Port,
		Protocol:   protocol,
		Pin:        wire.Pin,
		Password:   wire.Password,
		UserGroups: wire.UserGroups,
		ListenPort: wire.ListenPort,
		CallID:     wire.CallID,
	}, nil
}

func exposeProtocol(name string) (embed.ExposeProtocolType, error) {
	switch strings.ToLower(name) {
	case "", "http":
		return embed.ExposeProtocolHTTP, nil
	case "https":
		return embed.ExposeProtocolHTTPS, nil
	case "tcp":
		return embed.ExposeProtocolTCP, nil
	case "udp":
		return embed.ExposeProtocolUDP, nil
	case "tls":
		return embed.ExposeProtocolTLS, nil
	default:
		return 0, fmt.Errorf("unsupported expose protocol %q", name)
	}
}

// nb_new creates a new NetBird embedded client.
// Returns a handle > 0 on success, or -1 on error.
// On failure, use nb_create_errmsg to retrieve the error.
//
//export nb_new
func nb_new(
	setup_key *C.char,
	management_url *C.char,
	device_name *C.char,
	token *C.char,
	private_key *C.char,
	pre_shared_key *C.char,
	log_level *C.char,
	config_path *C.char,
	state_path *C.char,
	dns_labels_json *C.char,
	nat_external_ips_json *C.char,
	wireguard_port C.int,
	disable_client_routes C.int,
	block_inbound C.int,
	no_userspace C.int,
	disable_ipv6 C.int,
	enable_rosenpass C.int,
	rosenpass_permissive C.int,
	block_lan_access C.int,
	lazy_connection_enabled C.int,
	mtu C.int,
	preallocated_buffers_per_pool C.int,
	max_batch_size C.int,
) C.int {
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
	if private_key != nil {
		if pk := C.GoString(private_key); pk != "" {
			opts.PrivateKey = pk
		}
	}
	if pre_shared_key != nil {
		if psk := C.GoString(pre_shared_key); psk != "" {
			opts.PreSharedKey = psk
		}
	}
	if log_level != nil {
		if ll := C.GoString(log_level); ll != "" {
			opts.LogLevel = ll
		}
	}
	if config_path != nil {
		if cp := C.GoString(config_path); cp != "" {
			opts.ConfigPath = cp
		}
	}
	if state_path != nil {
		if sp := C.GoString(state_path); sp != "" {
			opts.StatePath = sp
		}
	}

	dnsLabels, err := parseJSONStringList(cStringOrEmpty(dns_labels_json))
	if err != nil {
		handleMu.Lock()
		lastCreateErr = fmt.Sprintf("parse dns labels: %v", err)
		handleMu.Unlock()
		return -1
	}
	natIPs, err := parseJSONStringList(cStringOrEmpty(nat_external_ips_json))
	if err != nil {
		handleMu.Lock()
		lastCreateErr = fmt.Sprintf("parse nat external ips: %v", err)
		handleMu.Unlock()
		return -1
	}
	mtuPtr, err := optUint16(int(mtu))
	if err != nil {
		handleMu.Lock()
		lastCreateErr = fmt.Sprintf("parse mtu: %v", err)
		handleMu.Unlock()
		return -1
	}
	preallocPtr, err := optUint32(int(preallocated_buffers_per_pool))
	if err != nil {
		handleMu.Lock()
		lastCreateErr = fmt.Sprintf("parse preallocated buffers: %v", err)
		handleMu.Unlock()
		return -1
	}
	maxBatchPtr, err := optUint32(int(max_batch_size))
	if err != nil {
		handleMu.Lock()
		lastCreateErr = fmt.Sprintf("parse max batch size: %v", err)
		handleMu.Unlock()
		return -1
	}

	if wireguard_port >= 0 {
		if wireguard_port > 65535 {
			handleMu.Lock()
			lastCreateErr = fmt.Sprintf("wireguard port %d out of range", int(wireguard_port))
			handleMu.Unlock()
			return -1
		}
		port := int(wireguard_port)
		opts.WireguardPort = &port
	}

	opts.DNSLabels = dnsLabels
	opts.NATExternalIPs = natIPs
	opts.DisableClientRoutes = disable_client_routes != 0
	opts.BlockInbound = block_inbound != 0
	opts.NoUserspace = no_userspace != 0
	opts.DisableIPv6 = disable_ipv6 != 0
	opts.EnableRosenpass = enable_rosenpass != 0
	opts.RosenpassPermissive = rosenpass_permissive != 0
	opts.BlockLANAccess = block_lan_access != 0
	opts.LazyConnectionEnabled = optBool(int(lazy_connection_enabled))
	opts.MTU = mtuPtr
	opts.Performance.PreallocatedBuffersPerPool = preallocPtr
	opts.Performance.MaxBatchSize = maxBatchPtr

	log.Infof("creating NetBird client with device name %q", opts.DeviceName)

	client, err := embed.New(opts)
	if err != nil {
		handleMu.Lock()
		lastCreateErr = err.Error()
		handleMu.Unlock()
		return -1
	}

	handleMu.Lock()
	defer handleMu.Unlock()
	handle := allocHandle()
	ctx, cancel := context.WithCancel(context.Background())
	clients[handle] = &clientState{
		client:      client,
		ctx:         ctx,
		cancel:      cancel,
		setupKey:    opts.SetupKey,
		jwtToken:    opts.JWTToken,
		deviceName:  opts.DeviceName,
		preallocSet: preallocEnabled(opts.Performance.PreallocatedBuffersPerPool),
		connSem:     make(chan struct{}, maxProxyConns),
	}
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

// preRegisterPeer registers the peer with the management server using direct
// gRPC calls. This bypasses the embed library's auth.Login() two-step flow
// (Login probe → Register) which can fail due to a server-side error handling
// bug where certain internal errors get mapped to codes.Internal, causing
// infinite reconnect retries.
//
// After pre-registration, embed.Client.Start() will find the peer already
// registered and proceed directly to engine startup.
func preRegisterPeer(client *embed.Client, setupKey, deviceName string) error {
	config, err := client.GetConfig()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	wgKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse wg key: %w", err)
	}

	pubSSHKey, err := ssh.GeneratePublicKey([]byte(config.SSHKey))
	if err != nil {
		return fmt.Errorf("generate ssh pub key: %w", err)
	}

	validSetupKey, err := uuid.Parse(setupKey)
	if err != nil {
		return fmt.Errorf("parse setup key: %w", err)
	}

	mgmTLS := config.ManagementURL.Scheme == "https"
	if !mgmTLS {
		log.Warnf("management URL %q is not https; the setup key crosses the network in plaintext", config.ManagementURL)
	}
	ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, deviceName)
	mgmClient, err := mgm.NewClient(ctx, config.ManagementURL.Host, wgKey, mgmTLS)
	if err != nil {
		return fmt.Errorf("mgm client: %w", err)
	}
	defer mgmClient.Close()

	// Registration establishes the peer's hostname/FQDN, so the device name
	// must be on the context here; patch.cfg.Login() would only see it later.
	sysInfo := system.GetInfo(ctx)

	_, err = mgmClient.Register(validSetupKey.String(), "", sysInfo, pubSSHKey, config.DNSLabels)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	log.Info("peer pre-registered successfully")
	return nil
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
	cs.clearError()

	// Pre-register with direct gRPC to avoid auth.Login() two-step bug
	cs.mu.Lock()
	setupKey := cs.setupKey
	deviceName := cs.deviceName
	if cs.ctx == nil || cs.ctx.Err() != nil {
		cs.ctx, cs.cancel = context.WithCancel(context.Background())
	}
	startCtx := cs.ctx
	cs.mu.Unlock()

	if setupKey != "" {
		if err := preRegisterPeer(cs.client, setupKey, deviceName); err != nil {
			log.Warnf("pre-registration failed (may already be registered): %v", err)
		}
	}

	if err := cs.client.Start(startCtx); err != nil {
		return setError(handle, err)
	}
	return 0
}

// nb_expose creates an expose session and writes its JSON description.
// Returns 0 on success, ERANGE if the buffer is too small, -1 on error.
// The call is idempotent for a given call id, so the Rust side can retry after
// ERANGE without creating a second session. A genuine second call carries a
// fresh call id and therefore creates a new session.
//
//export nb_expose
func nb_expose(handle C.int, request_json *C.char, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	req, err := parseExposeRequest(cStringOrEmpty(request_json))
	if err != nil {
		return setError(handle, err)
	}
	if cached := cs.findExpose(req.CallID); cached != nil {
		return writeJSON(cached, buf, buf_len)
	}

	callCtx, cancelCall := context.WithTimeout(cs.ctx, exposeTimeout)
	resp, err := cs.client.Expose(callCtx, embed.ExposeRequest{
		NamePrefix: req.NamePrefix,
		Domain:     req.Domain,
		Port:       req.Port,
		Protocol:   req.Protocol,
		Pin:        req.Pin,
		Password:   req.Password,
		UserGroups: req.UserGroups,
		ListenPort: req.ListenPort,
	})
	cancelCall()
	if err != nil {
		return setError(handle, err)
	}

	ctx, cancel := context.WithCancel(cs.ctx)

	data, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		ServiceName string `json:"service_name"`
		ServiceURL  string `json:"service_url"`
	}{resp.Domain, resp.ServiceName, resp.ServiceURL})
	if err != nil {
		cancel()
		teardownExpose(ctx, resp)
		return setError(handle, err)
	}

	entry := &exposeEntry{
		session:  resp,
		cancel:   cancel,
		done:     make(chan struct{}),
		callID:   req.CallID,
		response: data,
	}
	if err := cs.addExpose(resp.Domain, entry); err != nil {
		cancel()
		teardownExpose(ctx, resp)
		return setError(handle, err)
	}

	go func() {
		defer close(entry.done)
		_ = resp.Wait(ctx)
		cs.removeExpose(resp.Domain, entry)
	}()

	return writeJSON(data, buf, buf_len)
}

// nb_expose_stop terminates an expose session. It is idempotent: stopping an
// unknown or already stopped domain returns 0.
//
//export nb_expose_stop
func nb_expose_stop(handle C.int, domain *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	name := cStringOrEmpty(domain)

	cs.mu.Lock()
	entry, found := cs.exposes[name]
	if found {
		delete(cs.exposes, name)
	}
	cs.mu.Unlock()

	if !found {
		return 0
	}

	entry.cancel()
	<-entry.done
	return 0
}

// openCaptureFile creates a capture output file readable only by the owner,
// refusing to follow a pre-planted symlink.
func openCaptureFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|openNoFollow, 0o600)
}

// nb_capture_start starts a file-based packet capture and writes its JSON
// handle as {"id":n}. A previously running capture is stopped first.
// Returns 0 on success, ERANGE if the buffer is too small, -1 on error.
//
//export nb_capture_start
func nb_capture_start(handle C.int, options_json *C.char, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	opts, err := parseCaptureOptions(cStringOrEmpty(options_json))
	if err != nil {
		return setError(handle, err)
	}
	if opts.PcapPath == "" && opts.TextPath == "" {
		return setError(handle, fmt.Errorf("at least one of pcap_path or text_path is required"))
	}
	if opts.PcapPath != "" && opts.PcapPath == opts.TextPath {
		return setError(handle, fmt.Errorf("pcap_path and text_path must differ"))
	}

	cs.captureMu.Lock()
	defer cs.captureMu.Unlock()

	stopCaptures(cs.takeCaptures())

	id := allocCaptureID()

	var files []*os.File
	copts := embed.CaptureOptions{
		Filter:  opts.Filter,
		Verbose: opts.Verbose,
		ASCII:   opts.ASCII,
	}
	if opts.PcapPath != "" {
		f, err := openCaptureFile(opts.PcapPath)
		if err != nil {
			return setError(handle, err)
		}
		files = append(files, f)
		copts.Output = io.Writer(f)
	}
	if opts.TextPath != "" {
		f, err := openCaptureFile(opts.TextPath)
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return setError(handle, err)
		}
		files = append(files, f)
		copts.TextOutput = io.Writer(f)
	}

	sess, err := cs.client.StartCapture(copts)
	if err != nil {
		for _, f := range files {
			_ = f.Close()
		}
		return setError(handle, err)
	}

	entry := &captureEntry{sess: sess, files: files, id: C.int(id)}
	cs.mu.Lock()
	if cs.captures == nil {
		cs.captures = make(map[C.int]*captureEntry)
	}
	cs.captures[entry.id] = entry
	cs.mu.Unlock()

	data, err := json.Marshal(struct {
		ID int `json:"id"`
	}{id})
	if err != nil {
		return setError(handle, err)
	}
	return writeJSON(data, buf, buf_len)
}

// nb_capture_stats writes the counters of a capture session as JSON.
// Returns 0 on success, ERANGE if the buffer is too small, -1 on error.
//
//export nb_capture_stats
func nb_capture_stats(handle C.int, capture_id C.int, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	cs.mu.Lock()
	entry, found := cs.captures[capture_id]
	cs.mu.Unlock()
	if !found {
		return setError(handle, fmt.Errorf("capture session %d not found", int(capture_id)))
	}

	stats := entry.sess.Stats()
	data, err := json.Marshal(struct {
		Packets int64 `json:"packets"`
		Bytes   int64 `json:"bytes"`
		Dropped int64 `json:"dropped"`
	}{stats.Packets, stats.Bytes, stats.Dropped})
	if err != nil {
		return setError(handle, err)
	}
	return writeJSON(data, buf, buf_len)
}

// nb_capture_stop stops and closes a capture session.
// Returns 0 on success, -1 if the id is unknown.
//
//export nb_capture_stop
func nb_capture_stop(handle C.int, capture_id C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	cs.captureMu.Lock()
	cs.mu.Lock()
	entry, found := cs.captures[capture_id]
	if found {
		delete(cs.captures, capture_id)
	}
	cs.mu.Unlock()
	cs.captureMu.Unlock()
	if !found {
		return -1
	}

	entry.sess.Stop()
	<-entry.sess.Done()
	for _, f := range entry.files {
		_ = f.Close()
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
	cs.clearError()

	cs.mu.Lock()
	cancel := cs.cancel
	cleanups := cs.proxyCleanup
	cs.proxyCleanup = nil
	cs.mu.Unlock()

	stopExposes(cs.takeExposes())

	cs.captureMu.Lock()
	captures := cs.takeCaptures()
	cs.captureMu.Unlock()
	stopCaptures(captures)

	for _, fn := range cleanups {
		fn()
	}

	if cancel != nil {
		cancel()
	}

	ctx, cancelStop := context.WithTimeout(context.Background(), stopTimeout)
	defer cancelStop()
	if err := cs.client.Stop(ctx); err != nil {
		return setError(handle, err)
	}
	return 0
}

type StatusInfo struct {
	State                 string     `json:"state"`
	IP                    string     `json:"ip"`
	IPv6                  string     `json:"ipv6"`
	PubKey                string     `json:"pub_key"`
	FQDN                  string     `json:"fqdn"`
	WgPort                int        `json:"wg_port"`
	KernelInterface       bool       `json:"kernel_interface"`
	ManagementState       string     `json:"management_state"`
	SignalState           string     `json:"signal_state"`
	RosenpassEnabled      bool       `json:"rosenpass_enabled"`
	RosenpassPermissive   bool       `json:"rosenpass_permissive"`
	LazyConnectionEnabled bool       `json:"lazy_connection_enabled"`
	Peers                 []PeerInfo `json:"peers"`
	Error                 string     `json:"error,omitempty"`
}

type PeerInfo struct {
	IP                     string `json:"ip"`
	IPv6                   string `json:"ipv6"`
	PubKey                 string `json:"pub_key"`
	FQDN                   string `json:"fqdn"`
	ConnStatus             string `json:"conn_status"`
	Relayed                bool   `json:"relayed"`
	Latency                string `json:"latency"`
	LatencyNoise           string `json:"latency_noise"`
	BytesTx                int64  `json:"bytes_tx"`
	BytesRx                int64  `json:"bytes_rx"`
	LastWireguardHandshake string `json:"last_wireguard_handshake"`
	LocalIceCandidateType  string `json:"local_ice_candidate_type"`
	RemoteIceCandidateType string `json:"remote_ice_candidate_type"`
	RelayServerAddress     string `json:"relay_server_address"`
	RosenpassEnabled       bool   `json:"rosenpass_enabled"`
}

func formatHandshake(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func connStatusStr(s embed.PeerConnStatus) string {
	switch s {
	case embed.PeerStatusConnected:
		return "connected"
	case embed.PeerConnStatus(1): // StatusConnecting
		return "connecting"
	default:
		return "disconnected"
	}
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
	cs.clearError()

	fullStatus, err := cs.client.Status()
	if err != nil {
		return setError(handle, err)
	}

	peers := make([]PeerInfo, 0, len(fullStatus.Peers))
	for _, p := range fullStatus.Peers {
		peers = append(peers, PeerInfo{
			IP:                     p.IP,
			IPv6:                   p.IPv6,
			PubKey:                 p.PubKey,
			FQDN:                   p.FQDN,
			ConnStatus:             connStatusStr(p.ConnStatus),
			Relayed:                p.Relayed,
			Latency:                p.Latency.String(),
			LatencyNoise:           p.LatencyNoise.String(),
			BytesTx:                p.BytesTx,
			BytesRx:                p.BytesRx,
			LastWireguardHandshake: formatHandshake(p.LastWireguardHandshake),
			LocalIceCandidateType:  p.LocalIceCandidateType,
			RemoteIceCandidateType: p.RemoteIceCandidateType,
			RelayServerAddress:     p.RelayServerAddress,
			RosenpassEnabled:       p.RosenpassEnabled,
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

	state := "disconnected"
	if fullStatus.ManagementState.Connected && fullStatus.SignalState.Connected {
		state = "connected"
	} else if fullStatus.ManagementState.Connected || fullStatus.SignalState.Connected {
		state = "connecting"
	}

	info := StatusInfo{
		State:                 state,
		IP:                    fullStatus.LocalPeerState.IP,
		IPv6:                  fullStatus.LocalPeerState.IPv6,
		PubKey:                fullStatus.LocalPeerState.PubKey,
		FQDN:                  fullStatus.LocalPeerState.FQDN,
		WgPort:                fullStatus.LocalPeerState.WgPort,
		KernelInterface:       fullStatus.LocalPeerState.KernelInterface,
		ManagementState:       mgmtState,
		SignalState:           sigState,
		RosenpassEnabled:      fullStatus.RosenpassState.Enabled,
		RosenpassPermissive:   fullStatus.RosenpassState.Permissive,
		LazyConnectionEnabled: fullStatus.LazyConnectionEnabled,
		Peers:                 peers,
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
	cs.clearError()

	fullStatus, err := cs.client.Status()
	if err != nil {
		return setError(handle, err)
	}

	peers := make([]PeerInfo, 0, len(fullStatus.Peers))
	for _, p := range fullStatus.Peers {
		peers = append(peers, PeerInfo{
			IP:                     p.IP,
			IPv6:                   p.IPv6,
			PubKey:                 p.PubKey,
			FQDN:                   p.FQDN,
			ConnStatus:             connStatusStr(p.ConnStatus),
			Relayed:                p.Relayed,
			Latency:                p.Latency.String(),
			LatencyNoise:           p.LatencyNoise.String(),
			BytesTx:                p.BytesTx,
			BytesRx:                p.BytesRx,
			LastWireguardHandshake: formatHandshake(p.LastWireguardHandshake),
			LocalIceCandidateType:  p.LocalIceCandidateType,
			RemoteIceCandidateType: p.RemoteIceCandidateType,
			RelayServerAddress:     p.RelayServerAddress,
			RosenpassEnabled:       p.RosenpassEnabled,
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
	cs.clearError()

	goNet := cStringOrEmpty(net_type)
	goAddr := cStringOrEmpty(addr)

	if goNet != "tcp" && goNet != "udp" {
		return setError(handle, fmt.Errorf("unsupported network type: %q", goNet))
	}
	if goAddr == "" {
		return setError(handle, fmt.Errorf("dial address is required"))
	}

	ctx, cancel := context.WithTimeout(cs.ctx, dialTimeout)
	defer cancel()
	conn, err := cs.client.DialContext(ctx, goNet, goAddr)
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

// nb_dial_udp dials a peer over UDP through the mesh and returns a datagram
// socketpair FD, preserving message boundaries.
//
//export nb_dial_udp
func nb_dial_udp(handle C.int, addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	goAddr := cStringOrEmpty(addr)
	if goAddr == "" {
		return setError(handle, fmt.Errorf("dial address is required"))
	}

	ctx, cancel := context.WithTimeout(cs.ctx, dialTimeout)
	defer cancel()
	conn, err := cs.client.DialContext(ctx, "udp", goAddr)
	if err != nil {
		return setError(handle, err)
	}

	fds, err := createDatagramSocketPair()
	if err != nil {
		conn.Close()
		return setError(handle, err)
	}

	go pumpDatagramsConn(conn, fds[0])

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
	cs.clearError()

	goNet := cStringOrEmpty(net_type)
	goAddr := cStringOrEmpty(addr)

	if goNet != "tcp" {
		return setError(handle, fmt.Errorf("unsupported network type: %q", goNet))
	}
	if goAddr == "" {
		return setError(handle, fmt.Errorf("listen address is required"))
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

	registerListener(fds[1], func() { _ = listener.Close() })
	cs.mu.Lock()
	if cs.listeners == nil {
		cs.listeners = make(map[int]struct{})
	}
	cs.listeners[fds[1]] = struct{}{}
	cs.mu.Unlock()

	go acceptLoop(listener, fds[0])

	return C.int(fds[1])
}

// nb_listener_close stops a listener created by nb_listen. The caller keeps
// ownership of the signaling FD.
//
//export nb_listener_close
func nb_listener_close(fd C.int) {
	closeListener(int(fd))
}

// nb_listen_udp starts a UDP listener on a mesh address.
// Returns a file descriptor on success, -1 on error.
// Each datagram is forwarded over a SOCK_DGRAM socketpair, preserving
// message boundaries.
//
//export nb_listen_udp
func nb_listen_udp(handle C.int, addr *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	goAddr := cStringOrEmpty(addr)
	if goAddr == "" {
		return setError(handle, fmt.Errorf("listen address is required"))
	}

	packetConn, err := cs.client.ListenUDP(goAddr)
	if err != nil {
		return setError(handle, err)
	}

	fds, err := createDatagramSocketPair()
	if err != nil {
		packetConn.Close()
		return setError(handle, err)
	}

	go pumpDatagrams(packetConn, fds[0])

	return C.int(fds[1])
}

// nb_set_log_level changes the runtime log level.
// Returns 0 on success, -1 on error.
//
//export nb_set_log_level
func nb_set_log_level(handle C.int, level *C.char) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	goLevel := cStringOrEmpty(level)
	if err := cs.client.SetLogLevel(goLevel); err != nil {
		return setError(handle, err)
	}
	return 0
}

// nb_set_performance retunes a running client.
// Returns 0 on success, -1 on error.
//
//export nb_set_performance
func nb_set_performance(handle C.int, preallocated_buffers_per_pool C.int, max_batch_size C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	prealloc, err := optUint32(int(preallocated_buffers_per_pool))
	if err != nil {
		return setError(handle, err)
	}
	maxBatch, err := optUint32(int(max_batch_size))
	if err != nil {
		return setError(handle, err)
	}
	if maxBatch != nil {
		return setError(handle, fmt.Errorf("MaxBatchSize is construction-only and cannot be changed at runtime"))
	}

	cs.mu.Lock()
	enabled := cs.preallocSet
	cs.mu.Unlock()
	if !enabled {
		return setError(handle, fmt.Errorf("PreallocatedBuffersPerPool was not set at construction; runtime tuning has no effect"))
	}

	if err := cs.client.SetPerformance(embed.Performance{PreallocatedBuffersPerPool: prealloc}); err != nil {
		return setError(handle, err)
	}
	return 0
}

// nb_identity_for_ip writes the peer identity for an overlay IP as JSON.
// Returns 0 on success, ERANGE if buffer too small, -1 on error.
//
//export nb_identity_for_ip
func nb_identity_for_ip(handle C.int, ip *C.char, buf *C.char, buf_len C.int) C.int {
	cs, ok := getClient(handle)
	if !ok {
		return -1
	}
	cs.clearError()

	addr, err := netip.ParseAddr(cStringOrEmpty(ip))
	if err != nil {
		return setError(handle, err)
	}

	pubKey, fqdn, found := cs.client.IdentityForIP(addr)
	data, err := json.Marshal(struct {
		Found  bool   `json:"found"`
		PubKey string `json:"pub_key"`
		FQDN   string `json:"fqdn"`
	}{found, pubKey, fqdn})
	if err != nil {
		return setError(handle, err)
	}
	return writeJSON(data, buf, buf_len)
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
	cs.lastErr = ""
	cs.mu.Unlock()

	if msg == "" {
		msg = "no error"
	}
	writeCString(msg, buf, buf_len)
}

func writeCString(msg string, buf *C.char, bufLen C.int) {
	if buf == nil || bufLen <= 0 {
		return
	}
	needed := len(msg) + 1
	if int(bufLen) < needed {
		needed = int(bufLen)
		msg = msg[:needed-1]
	}
	if needed <= 0 {
		return
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
		cleanups := cs.proxyCleanup
		cs.proxyCleanup = nil
		listeners := make([]int, 0, len(cs.listeners))
		for fd := range cs.listeners {
			listeners = append(listeners, fd)
		}
		cs.listeners = nil
		cs.mu.Unlock()

		stopExposes(cs.takeExposes())

		cs.captureMu.Lock()
		captures := cs.takeCaptures()
		cs.captureMu.Unlock()
		stopCaptures(captures)

		for _, fn := range cleanups {
			fn()
		}
		for _, fd := range listeners {
			closeListener(fd)
		}

		if cancel != nil {
			cancel()
		}
		ctx, cancelStop := context.WithTimeout(context.Background(), stopTimeout)
		_ = cs.client.Stop(ctx)
		cancelStop()
	}
}

func main() {}
