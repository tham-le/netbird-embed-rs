//go:build android

package internal

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/wlynxg/anet"
)

type androidStubIFaceDiscover struct{}

type ifaceInfoStub struct {
	Name  string   `json:"name"`
	Index int      `json:"index"`
	MTU   int      `json:"mtu"`
	Addrs []string `json:"addrs"`
}

func (d *androidStubIFaceDiscover) IFaces() (string, error) {
	var ifaces []net.Interface
	var err error
	if runtime.GOOS == "android" {
		ifaces, err = anet.Interfaces()
	} else {
		ifaces, err = net.Interfaces()
	}
	if err != nil {
		return "", fmt.Errorf("enumerate interfaces: %w", err)
	}
	var infos []ifaceInfoStub
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var addrStrs []string
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		infos = append(infos, ifaceInfoStub{
			Name: iface.Name, Index: iface.Index, MTU: iface.MTU, Addrs: addrStrs,
		})
	}
	data, err := json.Marshal(infos)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type noopNetworkChangeListener struct{}

func (n *noopNetworkChangeListener) SetInterfaceIP(string) {}
func (n *noopNetworkChangeListener) OnNetworkChanged(string) {}

var _ listener.NetworkChangeListener = (*noopNetworkChangeListener)(nil)
