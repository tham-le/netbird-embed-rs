// Package kyvpnmobile provides a minimal gomobile-compatible API for KyVPN on Android.
//
// It wraps NetBird's embed client with Android-compatible stubs so the
// mesh networking works without VpnService or TunAdapter (userspace only).
//
// Usage from Kotlin:
//
//	val client = Kyvpnmobile.newClient(setupKey, mgmtUrl, deviceName, configDir)
//	client.start()
//	val peers = client.peers()  // JSON array
//	val proxyAddr = client.startProxy("100.91.x.x:8080")  // "127.0.0.1:PORT"
//	client.stop()
package kyvpnmobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/client/embed"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"
	sshcommon "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	"github.com/wlynxg/anet"
)

func init() {
	log.SetLevel(log.ErrorLevel)
	if runtime.GOOS == "android" {
		anet.SetAndroidVersion(0) // auto-detect
	}
}

// Client wraps NetBird embed for Android.
type Client struct {
	mu       sync.Mutex
	client   *embed.Client
	cancel   context.CancelFunc
	setupKey string
}

// PeerInfo holds info about a connected mesh peer.
type PeerInfo struct {
	IP          string `json:"ip"`
	FQDN        string `json:"fqdn"`
	Connected   bool   `json:"connected"`
	Relayed     bool   `json:"relayed"`
	Latency     string `json:"latency"`
	DisplayName string `json:"display_name"`
}

// NewClient creates a new KyVPN client. configDir should be the app's cache directory.
func NewClient(setupKey, managementURL, deviceName, configDir string) (*Client, error) {
	opts := embed.Options{
		SetupKey:      setupKey,
		ManagementURL: managementURL,
		DeviceName:    deviceName,
		LogLevel:      "error",
	}
	if configDir != "" {
		opts.ConfigPath = configDir + "/kyvpn_config.json"
		opts.StatePath = configDir + "/kyvpn_state.json"
	}

	port := 0
	opts.WireguardPort = &port

	client, err := embed.New(opts)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	// Pre-register peer via management API
	if setupKey != "" {
		preRegister(client, setupKey)
	}

	return &Client{
		client:   client,
		setupKey: setupKey,
	}, nil
}

// Start joins the mesh network. Blocks until connected or error.
func (c *Client) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()

	if err := c.client.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("start: %w", err)
	}
	return nil
}

// OverlayIP returns the local mesh overlay IP.
func (c *Client) OverlayIP() string {
	status, err := c.client.Status()
	if err != nil {
		return ""
	}
	ip := status.IP
	if idx := indexOf(ip, '/'); idx >= 0 {
		ip = ip[:idx]
	}
	return ip
}

// Peers returns a JSON array of connected peers.
func (c *Client) Peers() string {
	status, err := c.client.Status()
	if err != nil {
		return "[]"
	}
	var peers []PeerInfo
	for _, p := range status.Peers {
		if p.ConnStatus != embed.PeerStatusConnected {
			continue
		}
		ip := p.IP
		if idx := indexOf(ip, '/'); idx >= 0 {
			ip = ip[:idx]
		}
		name := p.FQDN
		if name == "" {
			name = ip
		}
		peers = append(peers, PeerInfo{
			IP:          ip,
			FQDN:        p.FQDN,
			Connected:   true,
			Relayed:     p.Relayed,
			Latency:     p.Latency.String(),
			DisplayName: name,
		})
	}
	if peers == nil {
		return "[]"
	}
	data, _ := json.Marshal(peers)
	return string(data)
}

// WaitForPeers blocks until at least one connected peer is found (up to 30s).
// Returns JSON array of connected peers.
func (c *Client) WaitForPeers() string {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		peers := c.Peers()
		if peers != "[]" {
			return peers
		}
		time.Sleep(time.Second)
	}
	return "[]"
}

// StartProxy starts a localhost TCP+UDP proxy to the given target (e.g. "100.91.x.x:8080").
// Returns "127.0.0.1:PORT" on success.
func (c *Client) StartProxy(target string) (string, error) {
	port, err := c.client.StartProxy(target)
	if err != nil {
		return "", fmt.Errorf("start proxy: %w", err)
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

// Stop disconnects from the mesh.
func (c *Client) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.client.Stop(context.Background())
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// preRegister does direct gRPC registration with the management server
// to avoid the two-step auth flow in embed.Client.Start().
func preRegister(client *embed.Client, setupKey string) {
	cfg := client.Config()
	if cfg == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mgmURL := cfg.ManagementURL.String()
	ctx = context.WithValue(ctx, system.DeviceNameCtxKey, "")

	mgmClient, err := mgm.NewClient(ctx, mgmURL, cfg.PrivateKey, nil)
	if err != nil {
		return
	}
	defer mgmClient.Close()

	sysInfo := system.GetInfo(ctx)
	pubSSH, _ := sshcommon.GeneratePublicKey(nil)

	privKey, _ := wgtypes.ParseKey(cfg.PrivateKey)
	pubKey := privKey.PublicKey().String()
	jwtToken := ""

	_, err = mgmClient.Register(ctx, setupKey, jwtToken, pubKey, pubSSH, sysInfo, &domain.LegacyPeerID{
		UID: uuid.New().String(),
	})
	if err != nil {
		// Not fatal — peer may already be registered
		log.Debugf("pre-register: %v", err)
	}
}
