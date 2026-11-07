package libbox

// Merging a v2rayNG-style array of Xray configs back into one profile.
//
// Exports such as "MASQUE-To-Xray" ship one complete Xray config per node:
// every element repeats the same log, DNS, inbounds, routing and helper
// outbounds and differs only in the proxy outbound. Saving one profile per
// element scatters the nodes; other profiles show them as one group. When the
// elements differ in exactly that one outbound, SplitCoreConfigArray merges
// them: every node becomes its own outbound (tagged by the element's remarks),
// rules that sent traffic to the proxy go to a routing balancer of the same
// tag, and the app shows that balancer as a selectable group whose "auto" entry
// follows leastPing (see readXrayGroups). Anything else keeps the split.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	xrayMergeStrategy      = "leastPing"
	xrayMergeProbeURL      = "https://www.gstatic.com/generate_204"
	xrayMergeProbeInterval = "10m"
)

// orderedObject is a JSON object that keeps its key order and raw values.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func parseOrderedObject(raw []byte) (*orderedObject, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("not a JSON object")
	}
	object := &orderedObject{values: map[string]json.RawMessage{}}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if _, seen := object.values[name]; !seen {
			object.keys = append(object.keys, name)
		}
		object.values[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return object, nil
}

func (o *orderedObject) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// set replaces key in place, or appends it when it is new.
func (o *orderedObject) set(key string, value json.RawMessage) {
	if !o.has(key) {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *orderedObject) remove(key string) {
	if !o.has(key) {
		return
	}
	delete(o.values, key)
	for i, name := range o.keys {
		if name == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *orderedObject) marshal() json.RawMessage {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			out.WriteByte(',')
		}
		name, _ := json.Marshal(key)
		out.Write(name)
		out.WriteByte(':')
		out.Write(o.values[key])
	}
	out.WriteByte('}')
	return out.Bytes()
}

func (o *orderedObject) stringValue(key string) string {
	var value string
	if raw, ok := o.values[key]; ok && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

// canonicalJSON re-encodes a value with sorted keys so equal values compare equal.
func canonicalJSON(raw json.RawMessage) (string, bool) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func rawArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	var items []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	return items, true
}

func mustRaw(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

// xrayMergeConfig is the parsed form of one element considered for merging.
type xrayMergeConfig struct {
	root      *orderedObject
	outbounds []json.RawMessage
}

// mergeXrayConfigArray returns the merged config and true when every element
// is an Xray config and they differ only in one outbound that keeps the same
// tag. remarks are the elements' trimmed remarks.
func mergeXrayConfigArray(elements []json.RawMessage, remarks []string) ([]byte, bool) {
	if len(elements) < 2 {
		return nil, false
	}
	configs := make([]xrayMergeConfig, len(elements))
	for i, element := range elements {
		if DetectCoreConfig(string(element)) != CoreXray {
			return nil, false
		}
		root, err := parseOrderedObject(bytes.TrimSpace(element))
		if err != nil {
			return nil, false
		}
		// Configs that already pick between nodes are left alone.
		if root.has("observatory") || root.has("burstObservatory") {
			return nil, false
		}
		outbounds, ok := rawArray(root.values["outbounds"])
		if !ok || len(outbounds) == 0 {
			return nil, false
		}
		configs[i] = xrayMergeConfig{root: root, outbounds: outbounds}
	}

	// Every top-level key except remarks and outbounds must be identical.
	first := configs[0]
	shared := map[string]string{}
	for _, key := range first.root.keys {
		if key == "remarks" || key == "outbounds" {
			continue
		}
		canonical, ok := canonicalJSON(first.root.values[key])
		if !ok {
			return nil, false
		}
		shared[key] = canonical
	}
	for _, config := range configs[1:] {
		count := 0
		for _, key := range config.root.keys {
			if key == "remarks" || key == "outbounds" {
				continue
			}
			want, ok := shared[key]
			if !ok {
				return nil, false
			}
			canonical, ok := canonicalJSON(config.root.values[key])
			if !ok || canonical != want {
				return nil, false
			}
			count++
		}
		if count != len(shared) || len(config.outbounds) != len(first.outbounds) {
			return nil, false
		}
	}

	// Exactly one outbound position may differ, and it keeps one tag.
	differing := -1
	for position := range first.outbounds {
		want, ok := canonicalJSON(first.outbounds[position])
		if !ok {
			return nil, false
		}
		for _, config := range configs[1:] {
			canonical, ok := canonicalJSON(config.outbounds[position])
			if !ok {
				return nil, false
			}
			if canonical != want {
				if differing >= 0 && differing != position {
					return nil, false
				}
				differing = position
			}
		}
	}
	if differing < 0 {
		return nil, false
	}
	nodes := make([]*orderedObject, len(configs))
	var groupTag string
	for i, config := range configs {
		node, err := parseOrderedObject(bytes.TrimSpace(config.outbounds[differing]))
		if err != nil {
			return nil, false
		}
		tag := node.stringValue("tag")
		if tag == "" || (i > 0 && tag != groupTag) {
			return nil, false
		}
		groupTag = tag
		nodes[i] = node
	}

	// The rest of the config may only reach the node through routing rules'
	// outboundTag, which become balancerTag; anything else (dialerProxy,
	// proxySettings, an existing balancer) keeps the split.
	routing, rules, ok := xrayMergeRouting(first.root)
	if !ok {
		return nil, false
	}
	usedTags := map[string]bool{groupTag: true}
	for position, raw := range first.outbounds {
		if position == differing {
			continue
		}
		if xrayMergeReferences(raw, groupTag) {
			return nil, false
		}
		var helper struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &helper)
		if helper.Tag != "" {
			usedTags[helper.Tag] = true
		}
	}
	for _, key := range first.root.keys {
		switch key {
		case "remarks", "outbounds", "routing":
			continue
		}
		if xrayMergeReferences(first.root.values[key], groupTag) {
			return nil, false
		}
	}

	// Node tags: the element's remarks, made unique and kept off other tags.
	tags := make([]string, len(nodes))
	for i := range nodes {
		base := strings.TrimSpace(remarks[i])
		if base == "" {
			base = fmt.Sprintf("%s %d", groupTag, i+1)
		}
		tag := base
		for suffix := 2; usedTags[tag]; suffix++ {
			tag = fmt.Sprintf("%s #%d", base, suffix)
		}
		usedTags[tag] = true
		tags[i] = tag
		nodes[i].set("tag", mustRaw(tag))
	}

	// Rules: outboundTag → balancerTag for the group. When the node was the
	// first outbound it also carried unmatched traffic, so a final rule keeps
	// that traffic on the group.
	var newRules []json.RawMessage
	for _, raw := range rules {
		rule, err := parseOrderedObject(bytes.TrimSpace(raw))
		if err != nil {
			return nil, false
		}
		if rule.stringValue("outboundTag") == groupTag {
			rule.remove("outboundTag")
			rule.set("balancerTag", mustRaw(groupTag))
		}
		newRules = append(newRules, rule.marshal())
	}
	if differing == 0 {
		newRules = append(newRules, mustRaw(map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": groupTag}))
	}
	routing.set("rules", mustRaw(newRules))
	routing.set("balancers", mustRaw([]any{map[string]any{
		"tag":      groupTag,
		"selector": tags,
		"strategy": map[string]any{"type": xrayMergeStrategy},
		// leastPing has no pick until the first probe round finishes.
		"fallbackTag": tags[0],
	}}))

	var outbounds []json.RawMessage
	for position, raw := range first.outbounds {
		if position != differing {
			outbounds = append(outbounds, raw)
			continue
		}
		for _, node := range nodes {
			outbounds = append(outbounds, node.marshal())
		}
	}

	merged := &orderedObject{keys: append([]string(nil), first.root.keys...), values: map[string]json.RawMessage{}}
	for key, value := range first.root.values {
		merged.values[key] = value
	}
	merged.remove("remarks")
	merged.set("outbounds", mustRaw(outbounds))
	merged.set("routing", routing.marshal())
	merged.set("observatory", mustRaw(map[string]any{
		"subjectSelector":   tags,
		"probeUrl":          xrayMergeProbeURL,
		"probeInterval":     xrayMergeProbeInterval,
		"enableConcurrency": true,
	}))
	return merged.marshal(), true
}

// xrayMergeRouting returns the routing object and its rules, refusing configs
// that already define balancers or whose rules use a balancerTag.
func xrayMergeRouting(root *orderedObject) (*orderedObject, []json.RawMessage, bool) {
	raw, ok := root.values["routing"]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return &orderedObject{values: map[string]json.RawMessage{}}, nil, true
	}
	routing, err := parseOrderedObject(bytes.TrimSpace(raw))
	if err != nil {
		return nil, nil, false
	}
	if balancers, ok := rawArray(routing.values["balancers"]); routing.has("balancers") && (!ok || len(balancers) > 0) {
		return nil, nil, false
	}
	var rules []json.RawMessage
	if routing.has("rules") {
		rules, ok = rawArray(routing.values["rules"])
		if !ok {
			return nil, nil, false
		}
	}
	for _, rule := range rules {
		var fields struct {
			BalancerTag string `json:"balancerTag"`
		}
		if json.Unmarshal(rule, &fields) != nil || fields.BalancerTag != "" {
			return nil, nil, false
		}
	}
	return routing, rules, true
}

// xrayMergeReferences reports whether raw names tag as a dialerProxy,
// a proxySettings tag or an outboundTag anywhere inside it.
func xrayMergeReferences(raw json.RawMessage, tag string) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	var walk func(value any, parent string) bool
	walk = func(value any, parent string) bool {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if text, ok := child.(string); ok && text == tag {
					switch {
					case key == "dialerProxy", key == "outboundTag", key == "balancerTag":
						return true
					case key == "tag" && parent == "proxySettings":
						return true
					}
				}
				if walk(child, key) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child, parent) {
					return true
				}
			}
		}
		return false
	}
	return walk(value, "")
}
