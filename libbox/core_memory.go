package libbox

// Memory held by a stopped core. mihomo keeps its whole runtime in package
// globals (tunnel rules, proxies, providers, DNS resolvers, the parsed
// GeoSite/GeoIP lists), so stopping it with hub/executor.Shutdown alone
// leaves everything the last profile loaded reachable until the next mihomo
// profile replaces it, often for the rest of the process. The service process
// then reported 500+ MB after switching between profiles of different cores.

import (
	"runtime"
	"runtime/debug"
	_ "unsafe" // go:linkname

	mihomoSingleflight "github.com/metacubex/mihomo/common/singleflight"
	mihomoRouter "github.com/metacubex/mihomo/component/geodata/router"

	mihomoGeodata "github.com/metacubex/mihomo/component/geodata"
	mihomoResolver "github.com/metacubex/mihomo/component/resolver"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoProvider "github.com/metacubex/mihomo/constant/provider"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	mihomoStatistic "github.com/metacubex/mihomo/tunnel/statistic"
)

// mihomoReleaseState drops everything a stopped mihomo profile left in
// mihomo's globals: open connections, rules and rule providers, proxies and
// proxy providers (their update loops stop through their finalizers), inbound
// listeners, the sniffer, the DNS resolvers and the GeoSite/GeoIP caches.
func mihomoReleaseState() {
	mihomoStatistic.DefaultManager.Range(func(tracker mihomoStatistic.Tracker) bool {
		_ = tracker.Close()
		return true
	})
	mihomoTunnel.UpdateRules(nil, nil, map[string]mihomoProvider.RuleProvider{})
	mihomoTunnel.UpdateProxies(map[string]mihomoConstant.Proxy{}, map[string]mihomoProvider.ProxyProvider{})
	mihomoTunnel.UpdateListeners(map[string]mihomoConstant.InboundListener{})
	mihomoTunnel.UpdateSniffer(nil)
	mihomoResolver.DefaultResolver = nil
	mihomoResolver.DefaultHostMapper = nil
	mihomoResolver.DefaultService = nil
	mihomoResolver.ProxyServerHostResolver = nil
	mihomoResolver.DirectHostResolver = nil
	mihomoClearGeoCaches()
}

// mihomoClearGeoCaches forgets every parsed GeoSite/GeoIP list and matcher.
// Only for a stopped mihomo: running GEOSITE/GEOIP rules look their matcher
// up in this cache on every match.
func mihomoClearGeoCaches() {
	mihomoGeodata.ClearGeoSiteCache()
	mihomoGeodata.ClearGeoIPCache()
}

// mihomo keeps the raw GeoSite domain list it built each matcher from
// (StoreResult singleflight) next to the matcher itself, for the life of the
// process. The running rules only use the matchers.
//
//go:linkname mihomoGeoSiteListCache github.com/metacubex/mihomo/component/geodata.loadGeoSiteMatcherListSF
var mihomoGeoSiteListCache mihomoSingleflight.Group[[]*mihomoRouter.Domain]

// mihomoDropGeoSiteLists drops the raw GeoSite lists once a config is applied
// and its matchers are built; a later rule that needs a list (a provider
// update, a new attribute filter) parses it again.
func mihomoDropGeoSiteLists() {
	mihomoGeoSiteListCache.Reset()
}

// releaseCoreMemory returns the memory a stopped core freed to the system,
// so the service's resident size drops right away instead of after the
// runtime's background scavenger catches up.
func releaseCoreMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
