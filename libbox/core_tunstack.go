package libbox

import (
	"bytes"
	"encoding/json"

	tun "github.com/sagernet/sing-tun"
)

// dropUnbuiltTunStack removes a tun inbound's "gvisor" or "mixed" stack when
// this build has no gVisor. sing-box 1.15 deprecates `stack` and runs
// sing-tun's own stack when it is unset, so many subscription generators'
// "mixed" would otherwise fail with ErrGVisorNotIncluded. The profile on disk
// is untouched; any other content is returned as is.
func dropUnbuiltTunStack(content string) string {
	if tun.WithGVisor || !bytes.Contains([]byte(content), []byte(`"stack"`)) {
		return content
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &root) != nil {
		return content
	}
	var inbounds []map[string]json.RawMessage
	if json.Unmarshal(root["inbounds"], &inbounds) != nil {
		return content
	}
	changed := false
	for _, inbound := range inbounds {
		var kind, stack string
		_ = json.Unmarshal(inbound["type"], &kind)
		_ = json.Unmarshal(inbound["stack"], &stack)
		if kind == "tun" && (stack == "gvisor" || stack == "mixed") {
			delete(inbound, "stack")
			changed = true
		}
	}
	if !changed {
		return content
	}
	encoded, err := json.Marshal(inbounds)
	if err != nil {
		return content
	}
	root["inbounds"] = encoded
	out, err := json.Marshal(root)
	if err != nil {
		return content
	}
	return string(out)
}
