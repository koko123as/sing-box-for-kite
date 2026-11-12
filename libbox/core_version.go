package libbox

import (
	"runtime/debug"
	"strings"

	mihomoConstant "github.com/metacubex/mihomo/constant"
	xrayCore "github.com/xtls/xray-core/core"
)

func xrayCoreVersion() string {
	return xrayCore.Version()
}

// mihomo's constant.Version is normally set by its own build flags; when it
// is not, read the module version libbox was built with.
func mihomoCoreVersion() string {
	if version := mihomoConstant.Version; version != "" && !strings.HasPrefix(version, "1.10") && version != "unknown version" {
		return strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == "github.com/metacubex/mihomo" {
				return strings.TrimPrefix(module.Version, "v")
			}
		}
	}
	return "unknown"
}
