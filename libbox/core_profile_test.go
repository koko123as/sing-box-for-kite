package libbox

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testVlessReality = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp#reality-node"
	testVlessXHTTP   = "vless://11111111-2222-3333-4444-555555555555@203.0.113.11:443?encryption=none&security=tls&sni=xh.example.com&type=xhttp&path=%2Fxh&mode=auto#xhttp-node"
	testShadowsocks  = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@203.0.113.12:8388#ss-node"
	testTrojanWS     = "trojan://secret@203.0.113.13:443?sni=t.example.com&type=ws&path=%2Fws&host=t.example.com#trojan-ws"
	testHysteria2    = "hysteria2://pass@203.0.113.14:443?sni=h.example.com&obfs=salamander&obfs-password=ob#hy2-node"
)

func TestDetectCoreConfig(t *testing.T) {
	cases := map[string]string{
		`{"outbounds":[{"type":"direct","tag":"direct"}]}`:                         CoreSingBox,
		`{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`:       CoreXray,
		"mixed-port: 7890\nproxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n": CoreMihomo,
		testVlessReality: CoreLinks,
		base64.StdEncoding.EncodeToString([]byte(testVlessReality + "\n" + testShadowsocks)): CoreLinks,
	}
	for content, want := range cases {
		if got := DetectCoreConfig(content); got != want {
			t.Errorf("DetectCoreConfig(%.40q) = %s, want %s", content, got, want)
		}
	}
}

func TestConvertLinksDefaultsToSingBox(t *testing.T) {
	links := strings.Join([]string{testVlessReality, testShadowsocks, testTrojanWS, testHysteria2}, "\n")
	profile, err := ConvertCoreShareLinks(base64.StdEncoding.EncodeToString([]byte(links)))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Core != CoreSingBox {
		t.Fatalf("core = %s, want sing-box", profile.Core)
	}
	var root struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(profile.Content), &root); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]map[string]any{}
	for _, outbound := range root.Outbounds {
		byTag[outbound["tag"].(string)] = outbound
	}
	for _, tag := range []string{"proxy", "auto", "reality-node", "ss-node", "trojan-ws", "hy2-node", "direct"} {
		if byTag[tag] == nil {
			t.Fatalf("missing outbound %s in %s", tag, profile.Content)
		}
	}
	reality := byTag["reality-node"]["tls"].(map[string]any)["reality"].(map[string]any)
	if reality["public_key"] != "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc" || byTag["reality-node"]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("reality node mapped wrong: %v", byTag["reality-node"])
	}
	if byTag["trojan-ws"]["transport"].(map[string]any)["type"] != "ws" {
		t.Fatalf("trojan ws transport missing: %v", byTag["trojan-ws"])
	}
	if err := CheckCoreConfig(CoreSingBox, profile.Content); err != nil {
		t.Fatal(err)
	}
}

func TestConvertLinksWithXHTTPUsesXray(t *testing.T) {
	profile, err := ConvertCoreShareLinks(testVlessReality + "\n" + testVlessXHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Core != CoreXray {
		t.Fatalf("core = %s, want xray", profile.Core)
	}
	if DetectCoreConfig(profile.Content) != CoreXray {
		t.Fatalf("converted Xray profile is not detected as Xray")
	}
	if strings.Contains(profile.Content, "sendThrough") {
		t.Fatalf("node name leaked into sendThrough: %s", profile.Content)
	}
	if !strings.Contains(profile.Content, `"xhttp-node"`) || !strings.Contains(profile.Content, `"xhttp"`) {
		t.Fatalf("xhttp node missing: %s", profile.Content)
	}
	if err := CheckCoreConfig(CoreXray, profile.Content); err != nil {
		t.Fatal(err)
	}
}

func TestCheckMihomoConfig(t *testing.T) {
	good := `mixed-port: 7890
proxies:
  - {name: a, type: ss, server: 203.0.113.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [a, DIRECT]}
rules:
  - MATCH,PROXY
`
	if err := CheckCoreConfig(CoreMihomo, good); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(good, "[a, DIRECT]", "[missing]", 1)
	if err := CheckCoreConfig(CoreMihomo, bad); err == nil {
		t.Fatal("unknown group member was accepted")
	}
	formatted, err := FormatCoreConfig(CoreMihomo, "# keep\r\n"+good)
	if err != nil || !strings.HasPrefix(formatted.Value, "# keep\n") {
		t.Fatalf("format dropped comments: %v %q", err, formatted)
	}
}

func TestCheckXrayConfigRejectsBadOutbound(t *testing.T) {
	bad := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a","port":"x"}]}}]}`
	if err := CheckCoreConfig(CoreXray, bad); err == nil {
		t.Fatal("bad Xray outbound was accepted")
	}
}

func TestResolveProfileCore(t *testing.T) {
	if core, _ := ResolveProfileCore(CoreAuto, `{"outbounds":[{"protocol":"freedom"}]}`); core != CoreXray {
		t.Fatalf("auto -> %s", core)
	}
	if core, _ := ResolveProfileCore(CoreMihomo, `{}`); core != CoreMihomo {
		t.Fatalf("explicit core not kept: %s", core)
	}
	if _, err := ResolveProfileCore(CoreAuto, testVlessReality); err == nil {
		t.Fatal("links resolved without conversion")
	}
}

func TestConvertLinksForMihomo(t *testing.T) {
	profile, err := ConvertCoreShareLinksFor(CoreMihomo, testVlessXHTTP+"\n"+testShadowsocks)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Core != CoreMihomo || DetectCoreConfig(profile.Content) != CoreMihomo {
		t.Fatalf("not a mihomo profile: %s", profile.Content)
	}
	if _, err := ConvertCoreShareLinksFor(CoreSingBox, testVlessXHTTP); err == nil {
		t.Fatal("sing-box accepted an xhttp node")
	}
}

func TestSubscriptionURLIsNotLinks(t *testing.T) {
	if got := DetectCoreConfig("https://example.com/sub?token=x"); got == CoreLinks {
		t.Fatal("subscription URL detected as share links")
	}
}
