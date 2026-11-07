package libbox

import (
	"encoding/json"
	"testing"

	tun "github.com/sagernet/sing-tun"
)

func TestDropUnbuiltTunStack(t *testing.T) {
	if tun.WithGVisor {
		t.Skip("built with gVisor")
	}
	in := `{"inbounds":[{"type":"tun","tag":"tun-in","stack":"mixed","mtu":9000},{"type":"mixed","tag":"mixed-in","listen_port":2412}],"outbounds":[{"type":"direct"}]}`
	var root struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(dropUnbuiltTunStack(in)), &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root.Inbounds[0]["stack"]; ok || root.Inbounds[0]["mtu"] != float64(9000) || root.Inbounds[1]["type"] != "mixed" {
		t.Fatalf("unexpected %v", root.Inbounds)
	}
	system := `{"inbounds":[{"type":"tun","stack":"system"}]}`
	if dropUnbuiltTunStack(system) != system || dropUnbuiltTunStack("not json") != "not json" {
		t.Fatal("must not touch other content")
	}
}

func TestConvertCoreShareLinksEnabled(t *testing.T) {
	link := "vless://a219bbfa-3a4a-4e24-a5e4-a4bdd2eb647d@example.com:443?encryption=none&type=ws&path=%2Fws&host=example.com&security=tls&sni=example.com#node"
	for enabled, want := range map[string]string{"sing-box,xray,mihomo": CoreSingBox, "xray,mihomo": CoreMihomo, "xray": CoreXray} {
		profile, err := ConvertCoreShareLinksEnabled(CoreAuto, enabled, link)
		if err != nil {
			t.Fatal(enabled, err)
		}
		if profile.Core != want {
			t.Fatalf("%s: got %s want %s", enabled, profile.Core, want)
		}
	}
	xhttp := "vless://a219bbfa-3a4a-4e24-a5e4-a4bdd2eb647d@example.com:443?encryption=none&type=xhttp&path=%2Fx&security=tls&sni=example.com#x"
	if _, err := ConvertCoreShareLinksEnabled(CoreAuto, "sing-box,mihomo", xhttp); err == nil {
		t.Fatal("xhttp must need Xray")
	}
}

func TestCoreProfileStats(t *testing.T) {
	yaml := "proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n  - {name: b, type: ss, server: 1.1.1.1, port: 2, cipher: aes-128-gcm, password: x}\nproxy-groups:\n  - {name: g, type: select, proxies: [a, b]}\nrules:\n  - MATCH,g\n"
	stats, err := CoreProfileStats(CoreMihomo, yaml)
	if err != nil || stats != `{"groups":1,"outbounds":2,"rules":1}` {
		t.Fatal(stats, err)
	}
	xray := `{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"tag":"b","selector":["d"]}],"rules":[{"outboundTag":"direct"},{"balancerTag":"b"}]}}`
	stats, err = CoreProfileStats(CoreXray, xray)
	if err != nil || stats != `{"groups":1,"outbounds":2,"rules":2}` {
		t.Fatal(stats, err)
	}
}
