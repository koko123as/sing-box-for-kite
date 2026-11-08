package libbox

import (
	"os"
	"runtime"
	"testing"

	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoExecutor "github.com/metacubex/mihomo/hub/executor"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
)

// TestCoreMemoryMihomoRelease measures what a stopped mihomo profile keeps on
// the heap, before and after mihomoReleaseState. It needs real GeoSite/GeoIP
// data, so it only runs when KITEBOX_MEMTEST_DIR names a directory holding
// GeoSite.dat and GeoIP.dat (MetaCubeX meta-rules-dat).
func TestCoreMemoryMihomoRelease(t *testing.T) {
	dir := os.Getenv("KITEBOX_MEMTEST_DIR")
	if dir == "" {
		t.Skip("KITEBOX_MEMTEST_DIR not set")
	}
	mihomoConstant.SetHomeDir(dir)
	heap := func() float64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.HeapAlloc) / (1 << 20)
	}
	content := `mode: rule
log-level: silent
geodata-mode: true
geo-auto-update: false
dns:
  enable: true
  nameserver: [223.5.5.5]
  nameserver-policy:
    "geosite:cn,private": [223.5.5.5]
    "geosite:geolocation-!cn": [8.8.8.8]
proxies:
  - {name: node, type: ss, server: 203.0.113.1, port: 8388, cipher: aes-128-gcm, password: test}
proxy-groups:
  - {name: PROXY, type: select, proxies: [node, DIRECT]}
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,google,PROXY
  - GEOSITE,geolocation-!cn,PROXY
  - GEOSITE,cn,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - GEOIP,cn,DIRECT
  - MATCH,PROXY
`
	apply := func() {
		config, err := mihomoConfig.Parse([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		mihomoExecutor.ApplyConfig(config, true)
	}
	stop := func() {
		mihomoExecutor.Shutdown()
		mihomoCloseListeners()
	}
	base := heap()

	// Before: start and stop as the service did (Shutdown + listeners only).
	apply()
	runningOld := heap()
	stop()
	stoppedOld := heap()
	mihomoReleaseState()
	released := heap()

	// After: the raw GeoSite lists are dropped once the config is applied,
	// and stopping releases mihomo's globals.
	apply()
	mihomoDropGeoSiteLists()
	runningNew := heap()
	// The running rules still match (they look their matchers up in the
	// cache that stays).
	matched := false
	for _, rule := range mihomoTunnel.Rules() {
		if rule.RuleType() == mihomoConstant.GEOSITE && rule.Payload() == "cn" {
			metadata := &mihomoConstant.Metadata{Host: "www.baidu.com"}
			matched, _ = rule.Match(metadata, mihomoConstant.RuleMatchHelper{})
		}
	}
	if !matched {
		t.Fatal("GEOSITE,cn no longer matches after the lists were dropped")
	}
	stop()
	mihomoReleaseState()
	stoppedNew := heap()

	t.Logf("heap MB: idle %.1f", base)
	t.Logf("heap MB before: running %.1f, after stop %.1f (kept until the next mihomo start)", runningOld, stoppedOld)
	t.Logf("heap MB after:  running %.1f, after stop %.1f (release of the old state alone: %.1f)", runningNew, stoppedNew, released)
	if runningNew > runningOld || stoppedNew > stoppedOld {
		t.Fatalf("release kept more memory: running %.1f > %.1f or stopped %.1f > %.1f", runningNew, runningOld, stoppedNew, stoppedOld)
	}
}
