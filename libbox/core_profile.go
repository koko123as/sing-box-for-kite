package libbox

// Multi-core profile handling: detect which core a profile belongs to,
// validate it with that core's own parser, format it, and turn Base64 node
// lists / share links into a complete profile.
//
// Sources reused instead of re-implemented:
//   - share links -> mihomo proxy maps: github.com/metacubex/mihomo/common/convert
//   - share links -> Xray outbounds: github.com/xtls/libxray/share (same Xray commit)
//   - Clash proxy -> sing-box outbound field mapping follows
//     github.com/SagerNet/serenity subscription/parser/clash.go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	mihomoAdapter "github.com/metacubex/mihomo/adapter"
	mihomoConvert "github.com/metacubex/mihomo/common/convert"
	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	mihomoConfig "github.com/metacubex/mihomo/config"
	"github.com/xtls/libxray/share"
	xrayConf "github.com/xtls/xray-core/infra/conf"
)

const (
	CoreAuto    = "auto"
	CoreSingBox = "sing-box"
	CoreXray    = "xray"
	CoreMihomo  = "mihomo"
	// CoreLinks is only a detection result: the content is a Base64 node list
	// or share links and must go through ConvertCoreShareLinks first.
	CoreLinks = "links"
)

func normalizeCoreContent(content string) string {
	content = strings.TrimPrefix(content, "\ufeff")
	return strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
}

// DetectCoreConfig reports which core a profile's content belongs to:
// Clash YAML -> mihomo; JSON whose inbounds/outbounds carry "protocol" -> Xray;
// a top-level JSON array of config objects -> array (split it first);
// other JSON -> sing-box; share links or a Base64 node list -> links.
func DetectCoreConfig(content string) string {
	text := normalizeCoreContent(content)
	if isCoreConfigArray(text) {
		return CoreArray
	}
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		if isXrayJSON(text) {
			return CoreXray
		}
		return CoreSingBox
	}
	if isClashYAML(text) {
		return CoreMihomo
	}
	if isShareLinks(text) {
		return CoreLinks
	}
	if decoded, err := mihomoConvert.TryDecodeBase64(text); err == nil {
		inner := normalizeCoreContent(string(decoded))
		if isShareLinks(inner) {
			return CoreLinks
		}
		if isClashYAML(inner) {
			return CoreMihomo
		}
	}
	return CoreSingBox
}

func isXrayJSON(text string) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &root) != nil {
		return false
	}
	for _, key := range []string{"outbounds", "inbounds"} {
		var items []map[string]json.RawMessage
		if json.Unmarshal(root[key], &items) != nil {
			continue
		}
		for _, item := range items {
			if _, ok := item["protocol"]; ok {
				return true
			}
		}
	}
	return false
}

func isClashYAML(text string) bool {
	var root map[string]any
	if mihomoYAML.Unmarshal([]byte(text), &root) != nil || len(root) == 0 {
		return false
	}
	for _, key := range []string{"proxies", "proxy-providers", "proxy-groups", "rules", "rule-providers", "mixed-port", "tun"} {
		if _, ok := root[key]; ok {
			return true
		}
	}
	return false
}

var coreShareSchemes = []string{
	// http:// and https:// are left out: a bare URL is a subscription to fetch,
	// not an HTTP proxy node.
	"vmess://", "vless://", "trojan://", "ss://", "ssr://", "socks://", "socks5://", "socks5h://",
	"hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://", "wireguard://", "wg://", "mieru://",
}

func isShareLinks(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		for _, scheme := range coreShareSchemes {
			if strings.HasPrefix(strings.ToLower(line), scheme) {
				return true
			}
		}
	}
	return false
}

// ResolveProfileCore turns a profile's declared core (auto or a concrete core)
// into the core that runs it. Share links never resolve here: convert first.
func ResolveProfileCore(declared string, content string) (string, error) {
	switch declared {
	case CoreSingBox, CoreXray, CoreMihomo:
		return declared, nil
	case "", CoreAuto:
		detected := DetectCoreConfig(content)
		if detected == CoreLinks {
			return "", fmt.Errorf("share links must be converted to a profile first")
		}
		if detected == CoreArray {
			return "", fmt.Errorf("a JSON array of configs must be split into profiles first")
		}
		return detected, nil
	default:
		return "", fmt.Errorf("unknown core: %s", declared)
	}
}

// CoreSubscriptionUserAgent returns the User-Agent a subscription request
// sends for the given core, so providers answer in that core's format.
func CoreSubscriptionUserAgent(core string, appVersion string) string {
	switch core {
	case CoreMihomo:
		return "clash.meta"
	case CoreXray:
		return "v2rayN/" + XrayVersion()
	default:
		return "sing-box " + Version() + " (" + appVersion + ")"
	}
}

// CoreDisplayName is the name the UI shows for a core.
func CoreDisplayName(core string) string {
	switch core {
	case CoreSingBox:
		return "sing-box"
	case CoreXray:
		return "Xray"
	case CoreMihomo:
		return "mihomo"
	default:
		return core
	}
}

// coreError prefixes err with the core that reported it, so a failed check
// or start says which core rejected the profile ("mihomo: ...").
func coreError(core string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", CoreDisplayName(core), err)
}

// CheckCoreConfig validates content with the parser of the given core. The
// error names the core that rejected it.
func CheckCoreConfig(core string, content string) error {
	switch core {
	case CoreSingBox:
		return coreError(core, CheckConfig(content))
	case CoreXray:
		return coreError(core, checkXrayConfig(content))
	case CoreMihomo:
		return coreError(core, checkMihomoConfig(content))
	case CoreLinks:
		return fmt.Errorf("share links must be converted to a profile first")
	case CoreArray:
		return fmt.Errorf("a JSON array of configs must be split into profiles first")
	default:
		return fmt.Errorf("unknown core: %s", core)
	}
}

// Xray: decode with Xray's own JSON loader and build every outbound and
// inbound. Routing and DNS read geosite:/geoip: from the shared geo directory
// while building; a missing file is only reported at start, since the app
// extracts its bundled copy before an Xray profile runs.
func checkXrayConfig(content string) error {
	if sWorkingPath != "" {
		_ = os.Setenv("xray.location.asset", GeoDataDir())
	}
	config, err := decodeXrayConfig(content)
	if err != nil {
		return err
	}
	if len(config.OutboundConfigs) == 0 {
		return fmt.Errorf("xray: no outbound")
	}
	for i := range config.OutboundConfigs {
		if _, err := config.OutboundConfigs[i].Build(); err != nil {
			return fmt.Errorf("xray outbound %d (%s): %w", i, config.OutboundConfigs[i].Tag, err)
		}
	}
	for i := range config.InboundConfigs {
		if _, err := config.InboundConfigs[i].Build(); err != nil {
			return fmt.Errorf("xray inbound %d (%s): %w", i, config.InboundConfigs[i].Tag, err)
		}
	}
	if config.DNSConfig != nil {
		if _, err := config.DNSConfig.Build(); err != nil && !isMissingGeoFile(err) {
			return fmt.Errorf("xray dns: %w", err)
		}
	}
	if config.RouterConfig != nil {
		if _, err := config.RouterConfig.Build(); err != nil && !isMissingGeoFile(err) {
			return fmt.Errorf("xray routing: %w", err)
		}
	}
	return nil
}

func decodeXrayConfig(content string) (*xrayConf.Config, error) {
	var config xrayConf.Config
	decoder := json.NewDecoder(strings.NewReader(normalizeCoreContent(content)))
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	return &config, nil
}

func isMissingGeoFile(err error) bool {
	message := err.Error()
	return (strings.Contains(message, "geosite") || strings.Contains(message, "geoip") || strings.Contains(message, ".dat")) &&
		(strings.Contains(message, "no such file") || strings.Contains(message, "not found") || strings.Contains(message, "failed to open"))
}

// mihomo: unmarshal with mihomo's raw config, then build every proxy with
// mihomo's adapter and check group references. Rules and providers are built
// by the full parse at start, which needs the geo databases (phase 2/4) and
// may download them, so it is not done while importing.
func checkMihomoConfig(content string) error {
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(normalizeCoreContent(content)))
	if err != nil {
		return fmt.Errorf("mihomo: %w", err)
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for i, mapping := range raw.Proxy {
		proxy, err := mihomoAdapter.ParseProxy(mapping)
		if err != nil {
			return fmt.Errorf("mihomo proxy %d: %w", i, err)
		}
		names[proxy.Name()] = true
	}
	if len(raw.Proxy) == 0 && len(raw.ProxyProvider) == 0 {
		return fmt.Errorf("mihomo: no proxies or proxy-providers")
	}
	for _, group := range raw.ProxyGroup {
		if name, ok := group["name"].(string); ok {
			names[name] = true
		}
	}
	for _, group := range raw.ProxyGroup {
		name, _ := group["name"].(string)
		if name == "" {
			return fmt.Errorf("mihomo: proxy group without name")
		}
		items, _ := group["proxies"].([]any)
		for _, item := range items {
			if member, ok := item.(string); ok && !names[member] {
				return fmt.Errorf("mihomo group %s: unknown proxy %s", name, member)
			}
		}
	}
	return nil
}

// FormatCoreConfig pretty-prints content in the format of the given core.
func FormatCoreConfig(core string, content string) (*StringBox, error) {
	switch core {
	case CoreSingBox:
		return FormatConfig(content)
	case CoreXray:
		var value any
		if err := json.Unmarshal([]byte(normalizeCoreContent(content)), &value); err != nil {
			return nil, fmt.Errorf("xray: %w", err)
		}
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			return nil, err
		}
		return wrapString(buffer.String()), nil
	case CoreMihomo:
		// Comments and key order are part of a Clash profile; only normalize
		// line endings and check that it still parses.
		text := normalizeCoreContent(content) + "\n"
		var root map[string]any
		if err := mihomoYAML.Unmarshal([]byte(text), &root); err != nil {
			return nil, fmt.Errorf("mihomo: %w", err)
		}
		return wrapString(text), nil
	default:
		return nil, fmt.Errorf("unknown core: %s", core)
	}
}

// UICoreProfile is a converted profile: the core that runs it and its content.
type UICoreProfile struct {
	Core    string
	Content string
}

// ConvertCoreShareLinks turns a Base64 node list or share links into a full
// profile. sing-box is the default; links using a transport only Xray has
// (xhttp) go to Xray.
func ConvertCoreShareLinks(content string) (*UICoreProfile, error) {
	return ConvertCoreShareLinksFor(CoreAuto, content)
}

// ConvertCoreShareLinksEnabled converts share links like ConvertCoreShareLinksFor,
// but for auto it only picks from enabled (comma-separated cores the user left
// on): xhttp links need Xray; others prefer sing-box, then mihomo, then Xray.
func ConvertCoreShareLinksEnabled(core string, enabled string, content string) (*UICoreProfile, error) {
	if core != "" && core != CoreAuto {
		return ConvertCoreShareLinksFor(core, content)
	}
	on := map[string]bool{}
	for _, item := range strings.Split(enabled, ",") {
		on[strings.TrimSpace(item)] = true
	}
	text := normalizeCoreContent(content)
	if !isShareLinks(text) {
		if decoded, err := mihomoConvert.TryDecodeBase64(text); err == nil {
			text = normalizeCoreContent(string(decoded))
		}
	}
	proxies, err := mihomoConvert.ConvertsV2Ray([]byte(text))
	if err != nil {
		return nil, err
	}
	for _, proxy := range proxies {
		if network, _ := proxy["network"].(string); xrayOnlyNetworks[network] {
			if !on[CoreXray] {
				return nil, fmt.Errorf("these nodes use %s, which only Xray supports, and the Xray core is turned off", network)
			}
			return ConvertCoreShareLinksFor(CoreXray, content)
		}
	}
	for _, candidate := range []string{CoreSingBox, CoreMihomo, CoreXray} {
		if on[candidate] {
			return ConvertCoreShareLinksFor(candidate, content)
		}
	}
	return nil, fmt.Errorf("every core is turned off")
}

// ConvertCoreShareLinksFor converts share links for a profile whose core the
// user chose; auto picks as ConvertCoreShareLinks does.
func ConvertCoreShareLinksFor(core string, content string) (*UICoreProfile, error) {
	text := normalizeCoreContent(content)
	if !isShareLinks(text) {
		if decoded, err := mihomoConvert.TryDecodeBase64(text); err == nil {
			text = normalizeCoreContent(string(decoded))
		}
	}
	proxies, err := mihomoConvert.ConvertsV2Ray([]byte(text))
	if err != nil {
		return nil, err
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}
	needsXray := false
	for _, proxy := range proxies {
		if network, _ := proxy["network"].(string); xrayOnlyNetworks[network] {
			needsXray = true
		}
	}
	switch core {
	case "", CoreAuto:
		if needsXray {
			return convertLinksToXray(text)
		}
		return convertLinksToSingBox(proxies)
	case CoreSingBox:
		if needsXray {
			return nil, fmt.Errorf("these nodes use xhttp, which sing-box does not support; choose Xray or auto")
		}
		return convertLinksToSingBox(proxies)
	case CoreXray:
		return convertLinksToXray(text)
	case CoreMihomo:
		return convertLinksToMihomo(proxies)
	default:
		return nil, fmt.Errorf("unknown core: %s", core)
	}
}

func convertLinksToMihomo(proxies []map[string]any) (*UICoreProfile, error) {
	var names []any
	for _, proxy := range proxies {
		names = append(names, proxy["name"])
	}
	profile := map[string]any{
		"mixed-port": 7890,
		"allow-lan":  false,
		"mode":       "rule",
		"log-level":  "warning",
		"ipv6":       true,
		"proxies":    proxies,
		"proxy-groups": []any{
			map[string]any{"name": "PROXY", "type": "select", "proxies": append([]any{"AUTO"}, names...)},
			map[string]any{"name": "AUTO", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300},
		},
		"rules": []any{"MATCH,PROXY"},
	}
	encoded, err := mihomoYAML.Marshal(profile)
	if err != nil {
		return nil, err
	}
	if err := checkMihomoConfig(string(encoded)); err != nil {
		return nil, err
	}
	return &UICoreProfile{Core: CoreMihomo, Content: string(encoded)}, nil
}

var xrayOnlyNetworks = map[string]bool{"xhttp": true, "splithttp": true}

func convertLinksToXray(text string) (*UICoreProfile, error) {
	// libXray >= v1.261031 returns {"outbounds": [...]} with only the fields it
	// projects; the second argument is an Age secret key (unused here).
	converted, err := share.ConvertShareLinksToXrayJson(text, "")
	if err != nil {
		return nil, fmt.Errorf("xray share links: %w", err)
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(converted))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("xray share links: %w", err)
	}
	var tags []string
	used := map[string]bool{"direct": true, "block": true}
	outbounds := make([]any, 0, len(document.Outbounds)+2)
	for i, outbound := range document.Outbounds {
		// The node name is the tag; older libXray kept it in sendThrough,
		// which is not a bind address either way.
		name, _ := outbound["tag"].(string)
		if sendThrough, ok := outbound["sendThrough"].(string); ok && name == "" {
			name = sendThrough
		}
		delete(outbound, "sendThrough")
		outbound["tag"] = uniqueTag(used, name, i)
		tags = append(tags, outbound["tag"].(string))
		outbounds = append(outbounds, outbound)
	}
	// Unset fields must not reach Xray as null (a null REALITY "dest" reads
	// as set and would build REALITY as a server). Drop them.
	outbounds = pruneJSONNulls(outbounds).([]any)
	outbounds = append(outbounds,
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole"},
	)
	profile := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"servers": []any{"https+local://1.1.1.1/dns-query", "8.8.8.8"}, "queryStrategy": "UseIP"},
		// Inbounds are replaced by the TUN inbound at start (phase 2).
		"inbounds":  []any{},
		"outbounds": outbounds,
		"observatory": map[string]any{
			"subjectSelector": tags,
			"probeURL":        "https://www.gstatic.com/generate_204",
			"probeInterval":   "5m",
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"balancers": []any{map[string]any{
				"tag":      "proxy",
				"selector": tags,
				"strategy": map[string]any{"type": "leastPing"},
			}},
			"rules": []any{
				map[string]any{"ip": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}, "outboundTag": "direct"},
				map[string]any{"network": "tcp,udp", "balancerTag": "proxy"},
			},
		},
	}
	encoded, err := marshalIndent(profile)
	if err != nil {
		return nil, err
	}
	if err := checkXrayConfig(encoded); err != nil {
		return nil, err
	}
	return &UICoreProfile{Core: CoreXray, Content: encoded}, nil
}

func convertLinksToSingBox(proxies []map[string]any) (*UICoreProfile, error) {
	used := map[string]bool{"proxy": true, "auto": true, "direct": true}
	var nodes []any
	var tags []string
	var firstErr error
	for i, proxy := range proxies {
		outbound, err := clashProxyToSingBox(proxy)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		name, _ := proxy["name"].(string)
		outbound["tag"] = uniqueTag(used, name, i)
		tags = append(tags, outbound["tag"].(string))
		nodes = append(nodes, outbound)
	}
	if len(nodes) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no nodes sing-box can run")
	}
	outbounds := []any{
		map[string]any{"type": "selector", "tag": "proxy", "outbounds": append([]string{"auto"}, tags...), "default": "auto"},
		map[string]any{"type": "urltest", "tag": "auto", "outbounds": tags},
	}
	outbounds = append(outbounds, nodes...)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	profile := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "tls", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
				map[string]any{"type": "local", "tag": "local"},
			},
			"final": "remote",
		},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in",
			"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true,
		}},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final":                   "proxy",
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
		},
	}
	encoded, err := marshalIndent(profile)
	if err != nil {
		return nil, err
	}
	if err := CheckConfig(encoded); err != nil {
		return nil, err
	}
	return &UICoreProfile{Core: CoreSingBox, Content: encoded}, nil
}

func pruneJSONNulls(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if item == nil {
				delete(v, key)
				continue
			}
			v[key] = pruneJSONNulls(item)
		}
		return v
	case []any:
		for i := range v {
			v[i] = pruneJSONNulls(v[i])
		}
		return v
	}
	return value
}

func uniqueTag(used map[string]bool, name string, index int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "node-" + strconv.Itoa(index+1)
	}
	tag := name
	for n := 2; used[tag]; n++ {
		tag = name + " " + strconv.Itoa(n)
	}
	used[tag] = true
	return tag
}

func marshalIndent(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// clashProxyToSingBox maps one mihomo proxy map (as produced by
// convert.ConvertsV2Ray) to a sing-box outbound object.
func clashProxyToSingBox(proxy map[string]any) (map[string]any, error) {
	kind := mapString(proxy, "type")
	server := mapString(proxy, "server")
	port, err := mapPort(proxy, "port")
	if err != nil && kind != "hysteria2" {
		return nil, fmt.Errorf("%s %s: %w", kind, mapString(proxy, "name"), err)
	}
	outbound := map[string]any{"server": server}
	if port > 0 {
		outbound["server_port"] = port
	}
	switch kind {
	case "ss":
		outbound["type"] = "shadowsocks"
		method := mapString(proxy, "cipher")
		if method == "dummy" {
			method = "none"
		}
		outbound["method"] = method
		outbound["password"] = mapString(proxy, "password")
		if plugin := mapString(proxy, "plugin"); plugin != "" {
			opts, _ := proxy["plugin-opts"].(map[string]any)
			switch plugin {
			case "obfs":
				outbound["plugin"] = "obfs-local"
				outbound["plugin_opts"] = pluginOptions(opts, "mode", "host")
			case "v2ray-plugin":
				outbound["plugin"] = "v2ray-plugin"
				outbound["plugin_opts"] = pluginOptions(opts, "mode", "tls", "host", "path")
			default:
				return nil, fmt.Errorf("shadowsocks plugin %s is not supported by sing-box", plugin)
			}
		}
		if mapBool(proxy, "udp-over-tcp") {
			outbound["udp_over_tcp"] = true
		}
	case "vmess":
		outbound["type"] = "vmess"
		outbound["uuid"] = mapString(proxy, "uuid")
		security := mapString(proxy, "cipher")
		if security == "" {
			security = "auto"
		}
		outbound["security"] = security
		if alterID, err := mapPort(proxy, "alterId"); err == nil && alterID > 0 {
			outbound["alter_id"] = alterID
		}
		if mapBool(proxy, "xudp") {
			outbound["packet_encoding"] = "xudp"
		}
		if tls := clashTLS(proxy, mapBool(proxy, "tls"), "servername"); tls != nil {
			outbound["tls"] = tls
		}
	case "vless":
		outbound["type"] = "vless"
		outbound["uuid"] = mapString(proxy, "uuid")
		if flow := mapString(proxy, "flow"); flow != "" {
			outbound["flow"] = flow
		}
		if encryption := mapString(proxy, "encryption"); encryption != "" && encryption != "none" {
			return nil, fmt.Errorf("vless encryption %s needs Xray", encryption)
		}
		outbound["packet_encoding"] = "xudp"
		if tls := clashTLS(proxy, mapBool(proxy, "tls"), "servername"); tls != nil {
			outbound["tls"] = tls
		}
	case "trojan":
		outbound["type"] = "trojan"
		outbound["password"] = mapString(proxy, "password")
		outbound["tls"] = clashTLS(proxy, true, "sni")
	case "hysteria2":
		outbound["type"] = "hysteria2"
		outbound["password"] = mapString(proxy, "password")
		if ports := mapString(proxy, "ports"); ports != "" {
			var serverPorts []string
			for _, item := range strings.Split(ports, ",") {
				if item = strings.TrimSpace(item); item != "" {
					serverPorts = append(serverPorts, strings.ReplaceAll(item, "-", ":"))
				}
			}
			outbound["server_ports"] = serverPorts
		} else if port == 0 {
			outbound["server_port"] = 443
		}
		if obfs := mapString(proxy, "obfs"); obfs != "" {
			outbound["obfs"] = map[string]any{"type": obfs, "password": mapString(proxy, "obfs-password")}
		}
		if up := mapMbps(proxy, "up"); up > 0 {
			outbound["up_mbps"] = up
		}
		if down := mapMbps(proxy, "down"); down > 0 {
			outbound["down_mbps"] = down
		}
		if _, ok := proxy["realm-opts"]; ok {
			return nil, fmt.Errorf("hysteria2 realm is not supported by sing-box")
		}
		outbound["tls"] = clashTLS(proxy, true, "sni")
	case "hysteria":
		outbound["type"] = "hysteria"
		outbound["auth_str"] = mapString(proxy, "auth-str")
		if obfs := mapString(proxy, "obfs"); obfs != "" {
			outbound["obfs"] = obfs
		}
		outbound["up_mbps"] = mapMbps(proxy, "up")
		outbound["down_mbps"] = mapMbps(proxy, "down")
		if protocol := mapString(proxy, "protocol"); protocol != "" && protocol != "udp" {
			return nil, fmt.Errorf("hysteria protocol %s is not supported by sing-box", protocol)
		}
		outbound["tls"] = clashTLS(proxy, true, "sni")
	case "tuic":
		outbound["type"] = "tuic"
		outbound["uuid"] = mapString(proxy, "uuid")
		outbound["password"] = mapString(proxy, "password")
		if mapString(proxy, "token") != "" && mapString(proxy, "uuid") == "" {
			return nil, fmt.Errorf("tuic v4 is not supported by sing-box")
		}
		if cc := mapString(proxy, "congestion-controller"); cc != "" {
			outbound["congestion_control"] = cc
		}
		if mode := mapString(proxy, "udp-relay-mode"); mode != "" {
			outbound["udp_relay_mode"] = mode
		}
		tls := clashTLS(proxy, true, "sni")
		if mapBool(proxy, "disable-sni") {
			tls["disable_sni"] = true
		}
		outbound["tls"] = tls
	case "anytls":
		outbound["type"] = "anytls"
		outbound["password"] = mapString(proxy, "password")
		outbound["tls"] = clashTLS(proxy, true, "sni")
	case "socks5":
		outbound["type"] = "socks"
		outbound["version"] = "5"
		if user := mapString(proxy, "username"); user != "" {
			outbound["username"] = user
			outbound["password"] = mapString(proxy, "password")
		}
		if mapBool(proxy, "tls") {
			return nil, fmt.Errorf("socks over TLS is not supported by sing-box")
		}
	case "http":
		outbound["type"] = "http"
		if user := mapString(proxy, "username"); user != "" {
			outbound["username"] = user
			outbound["password"] = mapString(proxy, "password")
		}
		if mapBool(proxy, "tls") {
			outbound["tls"] = clashTLS(proxy, true, "sni")
		}
	default:
		return nil, fmt.Errorf("%s nodes are not supported by sing-box", kind)
	}
	if kind == "ss" || kind == "socks5" || kind == "trojan" || kind == "vmess" || kind == "vless" {
		if !mapBool(proxy, "udp") {
			outbound["network"] = "tcp"
		}
	}
	if transport, err := clashTransport(proxy); err != nil {
		return nil, err
	} else if transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func clashTLS(proxy map[string]any, enabled bool, serverNameKey string) map[string]any {
	if !enabled {
		return nil
	}
	tls := map[string]any{"enabled": true}
	serverName := mapString(proxy, serverNameKey)
	if serverName == "" {
		serverName = mapString(proxy, "sni")
	}
	if serverName == "" {
		serverName = mapString(proxy, "servername")
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if mapBool(proxy, "skip-cert-verify") {
		tls["insecure"] = true
	}
	if alpn := mapStrings(proxy, "alpn"); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint := mapString(proxy, "client-fingerprint"); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if reality, ok := proxy["reality-opts"].(map[string]any); ok {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": mapString(reality, "public-key"),
			"short_id":   mapString(reality, "short-id"),
		}
		if _, ok := tls["utls"]; !ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
	}
	return tls
}

func clashTransport(proxy map[string]any) (map[string]any, error) {
	switch network := mapString(proxy, "network"); network {
	case "", "tcp":
		return nil, nil
	case "ws", "httpupgrade":
		opts, _ := proxy["ws-opts"].(map[string]any)
		headers := map[string]any{}
		if raw, ok := opts["headers"].(map[string]any); ok {
			for key, value := range raw {
				if text, ok := value.(string); ok && text != "" && !strings.EqualFold(key, "User-Agent") {
					headers[key] = text
				}
			}
		}
		path := mapString(opts, "path")
		if mapBool(opts, "v2ray-http-upgrade") || mapBool(opts, "v2ray-http-upgrade-fast-open") || network == "httpupgrade" {
			transport := map[string]any{"type": "httpupgrade", "path": path}
			if host, ok := headers["Host"]; ok {
				transport["host"] = host
				delete(headers, "Host")
			}
			if len(headers) > 0 {
				transport["headers"] = headers
			}
			return transport, nil
		}
		transport := map[string]any{"type": "ws", "path": path}
		if len(headers) > 0 {
			transport["headers"] = headers
		}
		if early, err := mapPort(opts, "max-early-data"); err == nil && early > 0 {
			transport["max_early_data"] = early
			transport["early_data_header_name"] = mapString(opts, "early-data-header-name")
		}
		return transport, nil
	case "grpc":
		opts, _ := proxy["grpc-opts"].(map[string]any)
		return map[string]any{"type": "grpc", "service_name": mapString(opts, "grpc-service-name")}, nil
	case "http":
		opts, _ := proxy["http-opts"].(map[string]any)
		transport := map[string]any{"type": "http"}
		if paths := mapStrings(opts, "path"); len(paths) > 0 {
			transport["path"] = paths[0]
		}
		if method := mapString(opts, "method"); method != "" {
			transport["method"] = method
		}
		if raw, ok := opts["headers"].(map[string]any); ok {
			if hosts := mapStrings(raw, "Host"); len(hosts) > 0 {
				transport["host"] = hosts
			}
		}
		return transport, nil
	case "h2":
		opts, _ := proxy["h2-opts"].(map[string]any)
		transport := map[string]any{"type": "http", "path": mapString(opts, "path")}
		if hosts := mapStrings(opts, "host"); len(hosts) > 0 {
			transport["host"] = hosts
		}
		return transport, nil
	default:
		return nil, fmt.Errorf("transport %s is not supported by sing-box", network)
	}
}

func pluginOptions(opts map[string]any, keys ...string) string {
	var parts []string
	for _, key := range keys {
		value, ok := opts[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case bool:
			if v {
				parts = append(parts, key)
			}
		default:
			parts = append(parts, key+"="+fmt.Sprint(v))
		}
	}
	return strings.Join(parts, ";")
}

func mapString(values map[string]any, key string) string {
	switch v := values[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func mapStrings(values map[string]any, key string) []string {
	switch v := values[key].(type) {
	case []string:
		var out []string
		for _, item := range v {
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range v {
			if text := fmt.Sprint(item); text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

func mapBool(values map[string]any, key string) bool {
	switch v := values[key].(type) {
	case bool:
		return v
	case string:
		parsed, _ := strconv.ParseBool(v)
		return parsed
	}
	return false
}

func mapPort(values map[string]any, key string) (int, error) {
	switch v := values[key].(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		if v == "" {
			return 0, fmt.Errorf("missing %s", key)
		}
		return strconv.Atoi(v)
	}
	return 0, fmt.Errorf("missing %s", key)
}

func mapMbps(values map[string]any, key string) int {
	text := strings.ToLower(strings.TrimSpace(mapString(values, key)))
	text = strings.TrimSuffix(strings.TrimSuffix(text, "mbps"), " ")
	value, _ := strconv.Atoi(strings.TrimSpace(text))
	return value
}

// Core versions shown in settings and about.
func XrayVersion() string {
	return xrayCoreVersion()
}

func MihomoVersion() string {
	return mihomoCoreVersion()
}

// mihomo's home; also the shared geo directory (GeoDataDir) Xray reads.
func coreAssetDir(workDir string, core string) string {
	dir := filepath.Join(workDir, "cores", core)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
