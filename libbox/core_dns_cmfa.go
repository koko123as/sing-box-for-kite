//go:build android && cmfa

package libbox

import (
	"net/netip"
	"strings"

	mihomoDNS "github.com/metacubex/mihomo/dns"
)

// UpdateCoreSystemDNS gives mihomo the underlying network's DNS servers,
// comma separated. Built with the cmfa tag (as ClashMetaForAndroid is),
// mihomo's "system" resolver reads them from here instead of the OS.
func UpdateCoreSystemDNS(servers string) {
	var list []string
	for _, server := range strings.Split(servers, ",") {
		if addr, err := netip.ParseAddr(strings.TrimSpace(server)); err == nil {
			list = append(list, netip.AddrPortFrom(addr, 53).String())
		}
	}
	mihomoDNS.UpdateSystemDNS(list)
	mihomoDNS.FlushCacheWithDefaultResolver()
}
