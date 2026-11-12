package libbox

// Link Xray and mihomo into libbox (phase 0: compile-only, not wired).
import (
	_ "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"

	_ "github.com/metacubex/mihomo/component/dialer"
	_ "github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor"
	_ "github.com/metacubex/mihomo/listener/sing_tun"
)
