//go:build android

package internal

func init() {
	androidRunOverride = func(c *ConnectClient, runningChan chan struct{}, logPath string) error {
		discover := &androidStubIFaceDiscover{}
		noop := &noopNetworkChangeListener{}
		return c.RunOnAndroidEmbed(discover, noop, runningChan)
	}
}
