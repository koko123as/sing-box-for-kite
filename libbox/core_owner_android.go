//go:build android

package libbox

// App (package name) routing for Xray and mihomo. Neither core can read
// /proc on recent Android, so both ask the app's VpnService for the owner of
// a connection (PlatformInterface.FindConnectionOwner, which uses
// ConnectivityManager.getConnectionOwnerUid) the way sing-box does. This only
// answers for connections that came in through this app's VPN TUN.

import (
	"errors"
	"strconv"
	"syscall"

	mihomoProcess "github.com/metacubex/mihomo/component/process"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	xrayNet "github.com/xtls/xray-core/common/net"
)

func init() {
	xrayNet.RegisterAndroidProcessFinder(func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
		name, err := coreConnectionPackage(network, srcIP, int32(srcPort), destIP, int32(destPort))
		if err != nil {
			return 0, "", "", err
		}
		return 0, name, "", nil
	})
	// Under the cmfa tag mihomo leaves package lookup to the embedding app.
	mihomoProcess.DefaultPackageNameResolver = func(metadata *mihomoConstant.Metadata) (string, error) {
		return coreConnectionPackage(metadata.NetWork.String(), metadata.SrcIP.String(), int32(metadata.SrcPort), metadata.DstIP.String(), int32(metadata.DstPort))
	}
}

func coreConnectionPackage(network, srcIP string, srcPort int32, destIP string, destPort int32) (string, error) {
	platform := coreProtector.Load()
	if platform == nil {
		return "", errors.New("no platform interface")
	}
	protocol := int32(syscall.IPPROTO_TCP)
	if network == "udp" {
		protocol = syscall.IPPROTO_UDP
	}
	owner, err := (*platform).FindConnectionOwner(protocol, srcIP, srcPort, destIP, destPort)
	if err != nil {
		return "", err
	}
	if len(owner.androidPackageNames) > 0 {
		return owner.androidPackageNames[0], nil
	}
	if owner.UserName != "" {
		return owner.UserName, nil
	}
	return "", errors.New("no package for uid " + strconv.Itoa(int(owner.UserId)))
}
