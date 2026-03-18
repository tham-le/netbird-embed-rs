//go:build android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/listener"
)

// RunOnAndroidEmbed is like RunOnAndroid but accepts a runningChan
// so embed.Client.Start() can detect when the engine is ready.
func (c *ConnectClient) RunOnAndroidEmbed(
	iFaceDiscover stdnet.ExternalIFaceDiscover,
	networkChangeListener listener.NetworkChangeListener,
	runningChan chan struct{},
) error {
	mobileDependency := MobileDependency{
		IFaceDiscover:         iFaceDiscover,
		NetworkChangeListener: networkChangeListener,
	}
	return c.run(mobileDependency, runningChan, "")
}
