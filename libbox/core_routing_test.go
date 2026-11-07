package libbox

import (
	"encoding/json"
	"strings"
	"testing"

	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoRules "github.com/metacubex/mihomo/rules"
	mihomoRulesCommon "github.com/metacubex/mihomo/rules/common"
)

const routingTestRules = `[
 {"remarks":"google","enabled":true,"domain":["google.com","full:www.example.org","geosite:netflix"],"ip":["8.8.8.8","geoip:us"],"target_type":"proxy","outbound":"Proxy"},
 {"remarks":"telegram app","enabled":true,"package":["org.telegram.messenger"],"port":"443,1000-2000","network":"tcp","target_type":"proxy","outbound":"Proxy"},
 {"remarks":"cn direct","enabled":true,"domain":["geosite:cn"],"target_type":"direct"},
 {"remarks":"ads","enabled":true,"domain":["keyword:adservice"],"target_type":"block"},
 {"remarks":"missing","enabled":true,"domain":["missing.example"],"target_type":"proxy","outbound":"NoSuchNode"},
 {"remarks":"off","enabled":false,"domain":["off.example"],"target_type":"block"},
 {"remarks":"bad","enabled":true,"ip":["not-an-ip"],"target_type":"block"}
]`

func TestCoreRoutingSingBox(t *testing.T) {
	content := `{
  // comment
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["node"]},
    {"type": "shadowsocks", "tag": "node", "server": "1.2.3.4", "server_port": 8388, "method": "aes-128-gcm", "password": "x"}
  ],
  "route": {"rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}, {"domain_suffix": ["x.com"], "outbound": "node"}]}
}`
	result, err := ApplyCoreRoutingRules(CoreSingBox, content, routingTestRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.warnings) != 2 {
		t.Fatalf("warnings: %q", result.warnings)
	}
	var root struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules   []map[string]any `json:"rules"`
			RuleSet []map[string]any `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(result.Content), &root); err != nil {
		t.Fatal(err)
	}
	rules := root.Route.Rules
	if len(rules) != 7 || rules[0]["action"] != "sniff" || rules[1]["action"] != "hijack-dns" {
		t.Fatalf("rules: %v", rules)
	}
	if rules[2]["outbound"] != "Proxy" || rules[2]["domain"] == nil || rules[2]["domain_suffix"] == nil || rules[2]["ip_cidr"] == nil || rules[2]["rule_set"] == nil {
		t.Fatalf("rule 2: %v", rules[2])
	}
	if rules[3]["package_name"] == nil || rules[3]["port"] == nil || rules[3]["port_range"] == nil || rules[3]["network"] == nil {
		t.Fatalf("rule 3: %v", rules[3])
	}
	if rules[4]["outbound"] != coreRuleDirectTag || rules[5]["action"] != "reject" {
		t.Fatalf("rules 4/5: %v %v", rules[4], rules[5])
	}
	if rules[6]["outbound"] != "node" {
		t.Fatalf("profile rule moved: %v", rules[6])
	}
	if len(root.Route.RuleSet) != 3 {
		t.Fatalf("rule sets: %v", root.Route.RuleSet)
	}
	if root.Outbounds[len(root.Outbounds)-1]["tag"] != coreRuleDirectTag {
		t.Fatalf("direct outbound missing: %v", root.Outbounds)
	}
	if err := CheckConfig(result.Content); err != nil {
		t.Fatalf("sing-box rejects the result: %v", err)
	}
}

func TestCoreRoutingXray(t *testing.T) {
	content := `{
  "outbounds": [
    {"tag": "Proxy", "protocol": "vless", "settings": {"vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]}},
    {"tag": "direct", "protocol": "freedom"}
  ],
  "routing": {"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "direct"}]}
}`
	result, err := ApplyCoreRoutingRules(CoreXray, content, routingTestRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.warnings) != 2 {
		t.Fatalf("warnings: %q", result.warnings)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(result.Content), &root); err != nil {
		t.Fatal(err)
	}
	rules := root["routing"].(map[string]any)["rules"].([]any)
	// google -> domain rule + ip rule; telegram; cn; ads; profile rule.
	if len(rules) != 6 {
		t.Fatalf("rules: %v", rules)
	}
	first := rules[0].(map[string]any)
	if first["outboundTag"] != "Proxy" || first["domain"] == nil || first["ip"] != nil {
		t.Fatalf("rule 0: %v", first)
	}
	second := rules[1].(map[string]any)
	if second["ip"] == nil || second["domain"] != nil {
		t.Fatalf("rule 1: %v", second)
	}
	app := rules[2].(map[string]any)
	if app["port"] != "443,1000-2000" || app["network"] != "tcp" || app["process"] == nil {
		t.Fatalf("rule 2: %v", app)
	}
	if rules[3].(map[string]any)["outboundTag"] != "direct" {
		t.Fatalf("rule 3 should reuse the profile's freedom outbound: %v", rules[3])
	}
	if rules[4].(map[string]any)["outboundTag"] != coreRuleBlockTag {
		t.Fatalf("rule 4: %v", rules[4])
	}
	if !xrayUsesProcessRules(root) {
		t.Fatal("process rules not detected")
	}
	if _, err := decodeXrayConfig(result.Content); err != nil {
		t.Fatalf("xray rejects the result: %v", err)
	}
}

func TestCoreRoutingMihomo(t *testing.T) {
	content := `# keep
mixed-port: 7890
proxies:
  - {name: node, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [node]}
rules:
  - MATCH,Proxy
`
	result, err := ApplyCoreRoutingRules(CoreMihomo, content, routingTestRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.warnings) != 2 {
		t.Fatalf("warnings: %q", result.warnings)
	}
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(result.Content))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DOMAIN,www.example.org,Proxy",
		"DOMAIN-SUFFIX,google.com,Proxy",
		"GEOSITE,netflix,Proxy",
		"IP-CIDR,8.8.8.8/32,Proxy",
		"GEOIP,US,Proxy",
		"AND,((PROCESS-NAME,org.telegram.messenger),(DST-PORT,443/1000-2000),(NETWORK,TCP)),Proxy",
		"GEOSITE,cn,DIRECT",
		"DOMAIN-KEYWORD,adservice,REJECT",
		"MATCH,Proxy",
	}
	if strings.Join(raw.Rule, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s", strings.Join(raw.Rule, "\n"))
	}
	if err := checkMihomoConfig(result.Content); err != nil {
		t.Fatalf("mihomo rejects the result: %v", err)
	}
	// Logic rules (domain OR ip, AND app/port/network) parse with mihomo's own
	// rule parser. GEO rules are left out: parsing them loads the databases.
	mixed, err := ApplyCoreRoutingRules(CoreMihomo, content, `[{"enabled":true,"domain":["a.com","regexp:^b\\.c$"],"ip":["10.0.0.0/8","2001:db8::/32"],"package":["com.x","com.y"],"network":"udp","outbound":"Proxy"}]`)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = mihomoConfig.UnmarshalRawConfig([]byte(mixed.Content))
	if err != nil {
		t.Fatal(err)
	}
	wantMixed := "AND,((OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-REGEX,^b\\.c$),(IP-CIDR,10.0.0.0/8),(IP-CIDR6,2001:db8::/32))),(OR,((PROCESS-NAME,com.x),(PROCESS-NAME,com.y))),(NETWORK,UDP)),Proxy"
	if raw.Rule[0] != wantMixed {
		t.Fatalf("mixed rule %s", raw.Rule[0])
	}
	for _, line := range []string{raw.Rule[0], want[1], want[3], want[5], want[7]} {
		tp, payload, target, params := mihomoRulesCommon.ParseRulePayload(line, true)
		if _, err := mihomoRules.ParseRule(tp, payload, target, params, nil); err != nil {
			t.Fatalf("mihomo cannot parse %q: %v", line, err)
		}
	}
}

func TestCoreRoutingTargets(t *testing.T) {
	targets, err := CoreProfileTargets(CoreMihomo, "proxies:\n  - {name: a, type: direct}\nproxy-groups:\n  - {name: G, type: select, proxies: [a]}\n")
	if err != nil || targets != "G\na" {
		t.Fatalf("mihomo targets %q %v", targets, err)
	}
	targets, err = CoreProfileTargets(CoreXray, `{"outbounds":[{"tag":"p","protocol":"vless"},{"tag":"b","protocol":"blackhole"}],"routing":{"balancers":[{"tag":"bal","selector":["p"]}]}}`)
	if err != nil || targets != "bal\np" {
		t.Fatalf("xray targets %q %v", targets, err)
	}
	targets, err = CoreProfileTargets(CoreSingBox, `{"outbounds":[{"type":"direct","tag":"d"},{"type":"selector","tag":"s","outbounds":["d"]},{"type":"block","tag":"x"}]}`)
	if err != nil || targets != "s\nd" {
		t.Fatalf("sing-box targets %q %v", targets, err)
	}
}

func TestCoreRoutingEmpty(t *testing.T) {
	result, err := ApplyCoreRoutingRules(CoreSingBox, "{}", "")
	if err != nil || result.Content != "{}" || len(result.warnings) != 0 {
		t.Fatalf("%v %v", result, err)
	}
	if _, err := ApplyCoreRoutingRules(CoreSingBox, "{}", "not json"); err == nil {
		t.Fatal("broken rule JSON accepted")
	}
}
