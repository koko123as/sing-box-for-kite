package libbox

// Default log level: when a profile does not set one, every core runs at
// warn (sing-box "warn", Xray "warning", mihomo "warning"). A level the
// profile sets explicitly is always kept. Only the content handed to the core
// changes; the profile on disk is untouched.

import (
	"bytes"
	"encoding/json"
	"strings"

	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	mihomoLog "github.com/metacubex/mihomo/log"
	"github.com/sagernet/sing-box/daemon"
)

const (
	coreDefaultLogLevel     = "warn"    // sing-box
	coreDefaultXrayLogLevel = "warning" // Xray and mihomo
)

// withDefaultSingBoxLogLevel adds log.level "warn" to a sing-box profile
// whose log section has no level. Values are copied byte for byte; content
// that is not a JSON object is returned as is.
func withDefaultSingBoxLogLevel(content string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if !strings.HasPrefix(trimmed, "{") {
		return content
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &root) != nil || root == nil {
		return content
	}
	logOptions := map[string]json.RawMessage{}
	if raw, ok := root["log"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if json.Unmarshal(raw, &logOptions) != nil || logOptions == nil {
			return content
		}
		if _, ok := logOptions["level"]; ok {
			return content
		}
	}
	logOptions["level"] = json.RawMessage(`"` + coreDefaultLogLevel + `"`)
	encoded, err := json.Marshal(logOptions)
	if err != nil {
		return content
	}
	root["log"] = encoded
	out, err := json.Marshal(root)
	if err != nil {
		return content
	}
	return string(out)
}

// xrayLogConfigWithDefault returns the log section Xray runs with: the
// profile's own, or loglevel "warning" when it sets none.
func xrayLogConfigWithDefault(root map[string]any) map[string]any {
	logConfig, _ := root["log"].(map[string]any)
	if logConfig == nil {
		logConfig = map[string]any{}
	}
	if level, ok := logConfig["loglevel"].(string); !ok || strings.TrimSpace(level) == "" {
		logConfig["loglevel"] = coreDefaultXrayLogLevel
	}
	return logConfig
}

// xrayDaemonLogLevel maps Xray's loglevel to the level reported to the app.
func xrayDaemonLogLevel(level string) daemon.LogLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return daemon.LogLevel_DEBUG
	case "info":
		return daemon.LogLevel_INFO
	case "error":
		return daemon.LogLevel_ERROR
	case "none":
		return daemon.LogLevel_PANIC
	default:
		return daemon.LogLevel_WARN
	}
}

// mihomoSetsLogLevel reports whether a Clash profile sets log-level itself.
func mihomoSetsLogLevel(content string) bool {
	var root map[string]any
	if mihomoYAML.Unmarshal([]byte(normalizeCoreContent(content)), &root) != nil {
		return false
	}
	_, ok := root["log-level"]
	return ok
}

func mihomoDaemonLogLevel(level mihomoLog.LogLevel) daemon.LogLevel {
	switch level {
	case mihomoLog.DEBUG:
		return daemon.LogLevel_DEBUG
	case mihomoLog.INFO:
		return daemon.LogLevel_INFO
	case mihomoLog.ERROR:
		return daemon.LogLevel_ERROR
	case mihomoLog.SILENT:
		return daemon.LogLevel_PANIC
	default:
		return daemon.LogLevel_WARN
	}
}
