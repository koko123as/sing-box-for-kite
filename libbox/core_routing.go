package libbox

// User routing rules (the v2rayNG "routing settings" idea) applied to whichever
// core runs a profile. The app keeps one rule list for every profile; at start
// and reload the rules are translated for the running core and put ahead of
// the profile's own rules. Only the content handed to the core changes, never
// the profile on disk. A rule whose target is not an outbound/group of the
// running profile is skipped with a warning; it never fails the start.
//
// Rule semantics (the same on every core):
//
//	(any domain OR any IP) AND (any app) AND port AND network
//
// Empty parts are left out. Domain entries: "full:", "domain:" (suffix, also
// the meaning of an entry without prefix), "keyword:", "regexp:", "geosite:".
// IP entries: an IP, a CIDR, or "geoip:<code>". Ports: "443", "1000-2000",
// comma separated. Network: "tcp", "udp" or both.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	sJSON "github.com/sagernet/sing/common/json"
	yaml "go.yaml.in/yaml/v3"
)

const (
	CoreRuleTargetProxy  = "proxy"
	CoreRuleTargetDirect = "direct"
	CoreRuleTargetBlock  = "block"

	coreRuleDirectTag = "kite-direct"
	coreRuleBlockTag  = "kite-block"

	singBoxGeositeURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"
	singBoxGeoIPURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-%s.srs"
)

type coreRoutingRule struct {
	Remarks    string   `json:"remarks"`
	Enabled    bool     `json:"enabled"`
	Domain     []string `json:"domain"`
	IP         []string `json:"ip"`
	Package    []string `json:"package"`
	Port       string   `json:"port"`
	Network    string   `json:"network"`
	TargetType string   `json:"target_type"`
	Outbound   string   `json:"outbound"`
}

// CoreRoutingResult is the content to run and the warnings to log.
type CoreRoutingResult struct {
	Content  string
	warnings []string
}

func (r *CoreRoutingResult) WarningCount() int32 { return int32(len(r.warnings)) }

func (r *CoreRoutingResult) Warning(index int32) string { return r.warnings[index] }

func (r *CoreRoutingResult) Warnings() string { return strings.Join(r.warnings, "\n") }

type parsedDomains struct {
	full, suffix, keyword, regex, geosite []string
}

func (d parsedDomains) empty() bool {
	return len(d.full)+len(d.suffix)+len(d.keyword)+len(d.regex)+len(d.geosite) == 0
}

type parsedIPs struct {
	cidr, geoip []string
}

func (i parsedIPs) empty() bool { return len(i.cidr)+len(i.geoip) == 0 }

type portSpec struct {
	single []uint16
	ranges [][2]uint16
}

func (p portSpec) empty() bool { return len(p.single)+len(p.ranges) == 0 }

type preparedRule struct {
	name     string
	domains  parsedDomains
	ips      parsedIPs
	packages []string
	ports    portSpec
	networks []string
	target   string // CoreRuleTarget*
	outbound string
}

func cleanList(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == ',' }) {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func parseRuleDomains(values []string) (parsedDomains, error) {
	var d parsedDomains
	for _, value := range cleanList(values) {
		kind, rest, found := strings.Cut(value, ":")
		if !found {
			kind, rest = "domain", value
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return d, fmt.Errorf("empty domain entry %q", value)
		}
		switch strings.ToLower(kind) {
		case "full":
			d.full = append(d.full, strings.ToLower(rest))
		case "domain":
			d.suffix = append(d.suffix, strings.ToLower(strings.TrimPrefix(rest, ".")))
		case "keyword":
			d.keyword = append(d.keyword, rest)
		case "regexp", "regex":
			d.regex = append(d.regex, rest)
		case "geosite":
			d.geosite = append(d.geosite, strings.ToLower(rest))
		default:
			return d, fmt.Errorf("unknown domain type %q", kind)
		}
	}
	return d, nil
}

func parseRuleIPs(values []string) (parsedIPs, error) {
	var i parsedIPs
	for _, value := range cleanList(values) {
		if code, ok := strings.CutPrefix(strings.ToLower(value), "geoip:"); ok {
			if code = strings.TrimSpace(code); code == "" {
				return i, fmt.Errorf("empty geoip entry")
			}
			i.geoip = append(i.geoip, code)
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			i.cidr = append(i.cidr, prefix.Masked().String())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return i, fmt.Errorf("invalid IP or CIDR %q", value)
		}
		i.cidr = append(i.cidr, netip.PrefixFrom(addr, addr.BitLen()).String())
	}
	return i, nil
}

func parseRulePorts(value string) (portSpec, error) {
	var p portSpec
	for _, part := range cleanList([]string{value}) {
		if from, to, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
			end, err2 := strconv.ParseUint(strings.TrimSpace(to), 10, 16)
			if err1 != nil || err2 != nil || start == 0 || start > end {
				return p, fmt.Errorf("invalid port range %q", part)
			}
			p.ranges = append(p.ranges, [2]uint16{uint16(start), uint16(end)})
			continue
		}
		port, err := strconv.ParseUint(part, 10, 16)
		if err != nil || port == 0 {
			return p, fmt.Errorf("invalid port %q", part)
		}
		p.single = append(p.single, uint16(port))
	}
	return p, nil
}

func parseRuleNetworks(value string) ([]string, error) {
	var out []string
	for _, part := range cleanList([]string{value}) {
		part = strings.ToLower(part)
		if part != "tcp" && part != "udp" {
			return nil, fmt.Errorf("invalid network %q", part)
		}
		out = append(out, part)
	}
	if len(out) == 2 {
		return nil, nil // tcp and udp: no restriction
	}
	return out, nil
}

func (p portSpec) xray() string {
	var parts []string
	for _, port := range p.single {
		parts = append(parts, strconv.Itoa(int(port)))
	}
	for _, r := range p.ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", r[0], r[1]))
	}
	return strings.Join(parts, ",")
}

func (p portSpec) mihomo() string {
	var parts []string
	for _, port := range p.single {
		parts = append(parts, strconv.Itoa(int(port)))
	}
	for _, r := range p.ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", r[0], r[1]))
	}
	return strings.Join(parts, "/")
}

// prepareRoutingRules parses the app's rule list; invalid or disabled rules
// are dropped (invalid ones with a warning).
func prepareRoutingRules(rulesJSON string) ([]preparedRule, []string, error) {
	rulesJSON = strings.TrimSpace(rulesJSON)
	if rulesJSON == "" {
		return nil, nil, nil
	}
	var rules []coreRoutingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, nil, fmt.Errorf("routing rules: %w", err)
	}
	var out []preparedRule
	var warnings []string
	for index, rule := range rules {
		if !rule.Enabled {
			continue
		}
		name := rule.Remarks
		if name == "" {
			name = "#" + strconv.Itoa(index+1)
		}
		fail := func(err error) {
			warnings = append(warnings, fmt.Sprintf("routing rule %s skipped: %v", name, err))
		}
		domains, err := parseRuleDomains(rule.Domain)
		if err != nil {
			fail(err)
			continue
		}
		ips, err := parseRuleIPs(rule.IP)
		if err != nil {
			fail(err)
			continue
		}
		ports, err := parseRulePorts(rule.Port)
		if err != nil {
			fail(err)
			continue
		}
		networks, err := parseRuleNetworks(rule.Network)
		if err != nil {
			fail(err)
			continue
		}
		packages := cleanList(rule.Package)
		if domains.empty() && ips.empty() && len(packages) == 0 && ports.empty() && len(networks) == 0 {
			fail(fmt.Errorf("no match condition"))
			continue
		}
		target := rule.TargetType
		switch target {
		case "", CoreRuleTargetProxy:
			target = CoreRuleTargetProxy
			if strings.TrimSpace(rule.Outbound) == "" {
				fail(fmt.Errorf("no target outbound"))
				continue
			}
		case CoreRuleTargetDirect, CoreRuleTargetBlock:
		default:
			fail(fmt.Errorf("unknown target type %q", target))
			continue
		}
		out = append(out, preparedRule{
			name: name, domains: domains, ips: ips, packages: packages,
			ports: ports, networks: networks, target: target, outbound: strings.TrimSpace(rule.Outbound),
		})
	}
	return out, warnings, nil
}

// ApplyCoreRoutingRules returns content with the app's routing rules (JSON
// array, see coreRoutingRule) put ahead of the profile's own rules,
// translated for core. Rules that cannot apply are reported as warnings.
func ApplyCoreRoutingRules(core string, content string, rulesJSON string) (*CoreRoutingResult, error) {
	rules, warnings, err := prepareRoutingRules(rulesJSON)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return &CoreRoutingResult{Content: content, warnings: warnings}, nil
	}
	var result string
	var more []string
	switch core {
	case CoreSingBox, "":
		result, more, err = applySingBoxRules(content, rules)
	case CoreXray:
		result, more, err = applyXrayRules(content, rules)
	case CoreMihomo:
		result, more, err = applyMihomoRules(content, rules)
	default:
		return nil, fmt.Errorf("unknown core: %s", core)
	}
	if err != nil {
		return nil, err
	}
	return &CoreRoutingResult{Content: result, warnings: append(warnings, more...)}, nil
}

// CoreProfileTargets lists the outbounds and groups a routing rule can send
// traffic to in a profile, one name per line (groups first).
func CoreProfileTargets(core string, content string) (string, error) {
	targets, err := coreProfileTargets(core, content)
	if err != nil {
		return "", err
	}
	return strings.Join(targets, "\n"), nil
}

func coreProfileTargets(core string, content string) ([]string, error) {
	switch core {
	case CoreSingBox, "":
		root, err := decodeJSONObject(content)
		if err != nil {
			return nil, err
		}
		var groups, nodes []string
		for _, key := range []string{"outbounds", "endpoints"} {
			items, _ := root[key].([]any)
			for _, item := range items {
				outbound, _ := item.(map[string]any)
				tag, _ := outbound["tag"].(string)
				kind, _ := outbound["type"].(string)
				if tag == "" {
					continue
				}
				switch kind {
				case "block", "dns":
				case "selector", "urltest":
					groups = append(groups, tag)
				default:
					nodes = append(nodes, tag)
				}
			}
		}
		return append(groups, nodes...), nil
	case CoreXray:
		root, err := decodeJSONObject(content)
		if err != nil {
			return nil, err
		}
		var groups, nodes []string
		routing, _ := root["routing"].(map[string]any)
		balancers, _ := routing["balancers"].([]any)
		for _, item := range balancers {
			balancer, _ := item.(map[string]any)
			if tag, _ := balancer["tag"].(string); tag != "" {
				groups = append(groups, tag)
			}
		}
		outbounds, _ := root["outbounds"].([]any)
		for _, item := range outbounds {
			outbound, _ := item.(map[string]any)
			tag, _ := outbound["tag"].(string)
			protocol, _ := outbound["protocol"].(string)
			if tag != "" && protocol != "dns" && protocol != "blackhole" {
				nodes = append(nodes, tag)
			}
		}
		return append(groups, nodes...), nil
	case CoreMihomo:
		var root struct {
			Proxies []struct {
				Name string `yaml:"name"`
			} `yaml:"proxies"`
			Groups []struct {
				Name string `yaml:"name"`
			} `yaml:"proxy-groups"`
		}
		if err := mihomoYAML.Unmarshal([]byte(normalizeCoreContent(content)), &root); err != nil {
			return nil, err
		}
		var out []string
		for _, group := range root.Groups {
			if group.Name != "" {
				out = append(out, group.Name)
			}
		}
		for _, proxy := range root.Proxies {
			if proxy.Name != "" {
				out = append(out, proxy.Name)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown core: %s", core)
	}
}

func decodeJSONObject(content string) (map[string]any, error) {
	data, err := io.ReadAll(sJSON.NewCommentFilter(strings.NewReader(normalizeCoreContent(content))))
	if err != nil {
		return nil, err
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("configuration is not a JSON object")
	}
	return root, nil
}

func targetSet(targets []string) map[string]bool {
	set := make(map[string]bool, len(targets))
	for _, target := range targets {
		set[target] = true
	}
	return set
}

func missingTargetWarning(rule preparedRule) string {
	return fmt.Sprintf("routing rule %s skipped: outbound %q is not in this profile", rule.name, rule.outbound)
}

// ---- sing-box ----

func applySingBoxRules(content string, rules []preparedRule) (string, []string, error) {
	root, err := decodeJSONObject(content)
	if err != nil {
		return "", nil, err
	}
	targets, _ := coreProfileTargets(CoreSingBox, content)
	known := targetSet(targets)
	route, _ := root["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
	}
	ruleSets, _ := route["rule_set"].([]any)
	ruleSetTags := map[string]bool{}
	for _, item := range ruleSets {
		if set, ok := item.(map[string]any); ok {
			if tag, _ := set["tag"].(string); tag != "" {
				ruleSetTags[tag] = true
			}
		}
	}
	// A direct outbound of the profile's own, or one added for the rules.
	directTag := ""
	outbounds, _ := root["outbounds"].([]any)
	for _, item := range outbounds {
		outbound, _ := item.(map[string]any)
		if kind, _ := outbound["type"].(string); kind == "direct" {
			if tag, _ := outbound["tag"].(string); tag != "" {
				directTag = tag
				break
			}
		}
	}
	var warnings []string
	var injected []any
	needDirect := false
	addRuleSet := func(prefix, code, urlFormat string) string {
		tag := prefix + "-" + code
		if !ruleSetTags[tag] {
			ruleSetTags[tag] = true
			set := map[string]any{
				"tag": tag, "type": "remote", "format": "binary",
				"url": fmt.Sprintf(urlFormat, code),
			}
			ruleSets = append(ruleSets, set)
		}
		return tag
	}
	for _, rule := range rules {
		item := map[string]any{}
		if len(rule.domains.full) > 0 {
			item["domain"] = rule.domains.full
		}
		if len(rule.domains.suffix) > 0 {
			item["domain_suffix"] = rule.domains.suffix
		}
		if len(rule.domains.keyword) > 0 {
			item["domain_keyword"] = rule.domains.keyword
		}
		if len(rule.domains.regex) > 0 {
			item["domain_regex"] = rule.domains.regex
		}
		if len(rule.ips.cidr) > 0 {
			item["ip_cidr"] = rule.ips.cidr
		}
		var sets []string
		for _, code := range rule.domains.geosite {
			sets = append(sets, addRuleSet("geosite", code, singBoxGeositeURL))
		}
		for _, code := range rule.ips.geoip {
			sets = append(sets, addRuleSet("geoip", code, singBoxGeoIPURL))
		}
		if len(sets) > 0 {
			item["rule_set"] = sets
		}
		if len(rule.packages) > 0 {
			item["package_name"] = rule.packages
		}
		if len(rule.ports.single) > 0 {
			item["port"] = rule.ports.single
		}
		if len(rule.ports.ranges) > 0 {
			var ranges []string
			for _, r := range rule.ports.ranges {
				ranges = append(ranges, fmt.Sprintf("%d:%d", r[0], r[1]))
			}
			item["port_range"] = ranges
		}
		if len(rule.networks) > 0 {
			item["network"] = rule.networks
		}
		switch rule.target {
		case CoreRuleTargetBlock:
			item["action"] = "reject"
		case CoreRuleTargetDirect:
			if directTag == "" {
				directTag = coreRuleDirectTag
				needDirect = true
			}
			item["action"] = "route"
			item["outbound"] = directTag
		default:
			if !known[rule.outbound] {
				warnings = append(warnings, missingTargetWarning(rule))
				continue
			}
			item["action"] = "route"
			item["outbound"] = rule.outbound
		}
		injected = append(injected, item)
	}
	if needDirect {
		root["outbounds"] = append(outbounds, map[string]any{"type": "direct", "tag": coreRuleDirectTag})
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	existing, _ := route["rules"].([]any)
	// Keep the profile's leading non-final actions (sniff, hijack-dns,
	// resolve, route-options) in front: the user rules need sniffed domains.
	insertAt := 0
	for insertAt < len(existing) {
		rule, _ := existing[insertAt].(map[string]any)
		action, _ := rule["action"].(string)
		protocol := rule["protocol"]
		if action == "sniff" || action == "hijack-dns" || action == "resolve" || action == "route-options" || protocol == "dns" {
			insertAt++
			continue
		}
		break
	}
	merged := make([]any, 0, len(existing)+len(injected))
	merged = append(merged, existing[:insertAt]...)
	merged = append(merged, injected...)
	merged = append(merged, existing[insertAt:]...)
	route["rules"] = merged
	root["route"] = route
	encoded, err := json.Marshal(root)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), warnings, nil
}

// ---- Xray ----

func applyXrayRules(content string, rules []preparedRule) (string, []string, error) {
	root, err := decodeJSONObject(content)
	if err != nil {
		return "", nil, err
	}
	outbounds, _ := root["outbounds"].([]any)
	routing, _ := root["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	outboundTags := map[string]bool{}
	directTag, blockTag := "", ""
	for _, item := range outbounds {
		outbound, _ := item.(map[string]any)
		tag, _ := outbound["tag"].(string)
		protocol, _ := outbound["protocol"].(string)
		if tag == "" {
			continue
		}
		outboundTags[tag] = true
		if protocol == "freedom" && directTag == "" {
			directTag = tag
		}
		if protocol == "blackhole" && blockTag == "" {
			blockTag = tag
		}
	}
	balancerTags := map[string]bool{}
	balancers, _ := routing["balancers"].([]any)
	for _, item := range balancers {
		balancer, _ := item.(map[string]any)
		if tag, _ := balancer["tag"].(string); tag != "" {
			balancerTags[tag] = true
		}
	}
	var warnings []string
	var injected []any
	for _, rule := range rules {
		base := map[string]any{"type": "field", "ruleTag": "kite: " + rule.name}
		switch rule.target {
		case CoreRuleTargetDirect:
			if directTag == "" {
				directTag = coreRuleDirectTag
				outbounds = append(outbounds, map[string]any{"tag": coreRuleDirectTag, "protocol": "freedom"})
			}
			base["outboundTag"] = directTag
		case CoreRuleTargetBlock:
			if blockTag == "" {
				blockTag = coreRuleBlockTag
				outbounds = append(outbounds, map[string]any{"tag": coreRuleBlockTag, "protocol": "blackhole"})
			}
			base["outboundTag"] = blockTag
		default:
			switch {
			case outboundTags[rule.outbound]:
				base["outboundTag"] = rule.outbound
			case balancerTags[rule.outbound]:
				base["balancerTag"] = rule.outbound
			default:
				warnings = append(warnings, missingTargetWarning(rule))
				continue
			}
		}
		if len(rule.packages) > 0 {
			// Matched through RegisterAndroidProcessFinder (core_owner_android.go).
			base["process"] = rule.packages
		}
		if !rule.ports.empty() {
			base["port"] = rule.ports.xray()
		}
		if len(rule.networks) > 0 {
			base["network"] = strings.Join(rule.networks, ",")
		}
		var domains []string
		for _, value := range rule.domains.full {
			domains = append(domains, "full:"+value)
		}
		for _, value := range rule.domains.suffix {
			domains = append(domains, "domain:"+value)
		}
		for _, value := range rule.domains.keyword {
			domains = append(domains, "keyword:"+value)
		}
		for _, value := range rule.domains.regex {
			domains = append(domains, "regexp:"+value)
		}
		for _, value := range rule.domains.geosite {
			domains = append(domains, "geosite:"+value)
		}
		var ips []string
		ips = append(ips, rule.ips.cidr...)
		for _, value := range rule.ips.geoip {
			ips = append(ips, "geoip:"+value)
		}
		// Xray ANDs domain and ip inside one rule; the shared semantics are
		// domain OR ip, so each gets its own rule.
		emitted := false
		if len(domains) > 0 {
			item := cloneMap(base)
			item["domain"] = domains
			injected = append(injected, item)
			emitted = true
		}
		if len(ips) > 0 {
			item := cloneMap(base)
			item["ip"] = ips
			injected = append(injected, item)
			emitted = true
		}
		if !emitted {
			injected = append(injected, base)
		}
	}
	root["outbounds"] = outbounds
	existing, _ := routing["rules"].([]any)
	routing["rules"] = append(injected, existing...)
	root["routing"] = routing
	encoded, err := json.Marshal(root)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), warnings, nil
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

// xrayUsesProcessRules reports whether a translated Xray config routes by app.
func xrayUsesProcessRules(root map[string]any) bool {
	routing, _ := root["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		if rule, ok := item.(map[string]any); ok {
			if _, has := rule["process"]; has {
				return true
			}
		}
	}
	return false
}

// ---- mihomo ----

func applyMihomoRules(content string, rules []preparedRule) (string, []string, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(normalizeCoreContent(content)), &document); err != nil {
		return "", nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return "", nil, fmt.Errorf("mihomo configuration is not a mapping")
	}
	mapping := document.Content[0]
	targets, _ := coreProfileTargets(CoreMihomo, content)
	known := targetSet(targets)
	var warnings []string
	var lines []string
	for _, rule := range rules {
		var target string
		switch rule.target {
		case CoreRuleTargetDirect:
			target = "DIRECT"
		case CoreRuleTargetBlock:
			target = "REJECT"
		default:
			if !known[rule.outbound] && rule.outbound != "DIRECT" && rule.outbound != "REJECT" {
				warnings = append(warnings, missingTargetWarning(rule))
				continue
			}
			if strings.ContainsAny(rule.outbound, ",()") {
				warnings = append(warnings, fmt.Sprintf("routing rule %s skipped: mihomo rules cannot name %q (contains , or parentheses)", rule.name, rule.outbound))
				continue
			}
			target = rule.outbound
		}
		generated, err := mihomoRuleLines(rule, target)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("routing rule %s skipped: %v", rule.name, err))
			continue
		}
		lines = append(lines, generated...)
	}
	var rulesNode *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == "rules" {
			rulesNode = mapping.Content[index+1]
			break
		}
	}
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if rulesNode == nil {
			mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}, node)
		} else {
			*rulesNode = *node
		}
		rulesNode = node
		for index := 0; index+1 < len(mapping.Content); index += 2 {
			if mapping.Content[index].Value == "rules" {
				rulesNode = mapping.Content[index+1]
			}
		}
	}
	var injected []*yaml.Node
	for _, line := range lines {
		injected = append(injected, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: line})
	}
	rulesNode.Content = append(injected, rulesNode.Content...)
	encoded, err := yaml.Marshal(&document)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), warnings, nil
}

func mihomoRuleLines(rule preparedRule, target string) ([]string, error) {
	var match []string // domain OR ip
	for _, value := range rule.domains.full {
		match = append(match, "DOMAIN,"+value)
	}
	for _, value := range rule.domains.suffix {
		match = append(match, "DOMAIN-SUFFIX,"+value)
	}
	for _, value := range rule.domains.keyword {
		match = append(match, "DOMAIN-KEYWORD,"+value)
	}
	for _, value := range rule.domains.regex {
		if strings.ContainsAny(value, ",()") {
			return nil, fmt.Errorf("mihomo regex %q contains , or parentheses", value)
		}
		match = append(match, "DOMAIN-REGEX,"+value)
	}
	for _, value := range rule.domains.geosite {
		match = append(match, "GEOSITE,"+value)
	}
	for _, value := range rule.ips.cidr {
		prefix := netip.MustParsePrefix(value)
		if prefix.Addr().Is6() {
			match = append(match, "IP-CIDR6,"+value)
		} else {
			match = append(match, "IP-CIDR,"+value)
		}
	}
	for _, value := range rule.ips.geoip {
		match = append(match, "GEOIP,"+strings.ToUpper(value))
	}
	var apps []string
	for _, value := range rule.packages {
		// Matched through process.DefaultPackageNameResolver (core_owner_android.go).
		apps = append(apps, "PROCESS-NAME,"+value)
	}
	var extra []string
	if !rule.ports.empty() {
		extra = append(extra, "DST-PORT,"+rule.ports.mihomo())
	}
	if len(rule.networks) == 1 {
		extra = append(extra, "NETWORK,"+strings.ToUpper(rule.networks[0]))
	}
	// One plain condition list (only one part set): one rule per entry.
	parts := 0
	for _, part := range [][]string{match, apps, extra} {
		if len(part) > 0 {
			parts++
		}
	}
	if parts == 1 && len(extra) == 0 {
		var out []string
		for _, condition := range append(match, apps...) {
			out = append(out, condition+","+target)
		}
		return out, nil
	}
	group := func(conditions []string) string {
		if len(conditions) == 1 {
			return "(" + conditions[0] + ")"
		}
		var wrapped []string
		for _, condition := range conditions {
			wrapped = append(wrapped, "("+condition+")")
		}
		return "(OR,(" + strings.Join(wrapped, ",") + "))"
	}
	var and []string
	if len(match) > 0 {
		and = append(and, group(match))
	}
	if len(apps) > 0 {
		and = append(and, group(apps))
	}
	for _, condition := range extra {
		and = append(and, "("+condition+")")
	}
	if len(and) == 1 {
		// A single OR group (or a single extra condition).
		inner := strings.TrimSuffix(strings.TrimPrefix(and[0], "("), ")")
		return []string{inner + "," + target}, nil
	}
	return []string{"AND,(" + strings.Join(and, ",") + ")," + target}, nil
}
