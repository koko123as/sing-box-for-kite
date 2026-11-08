package libbox

// A top-level JSON array of complete configs, as v2rayNG exports and some
// subscriptions serve them ("custom config" lists): each element is its own
// profile, named by its "remarks". The app splits the array before saving;
// a single profile never stores an array.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// CoreArray is only a detection result, like CoreLinks: the content is a JSON
// array of configs and must be split with SplitCoreConfigArray first.
const CoreArray = "array"

// CoreConfigEntries is the result of SplitCoreConfigArray. gomobile cannot
// return slices, so entries are read by index.
type CoreConfigEntries struct {
	entries []coreConfigEntry
}

type coreConfigEntry struct {
	remarks string
	content string
	core    string
}

func (e *CoreConfigEntries) Len() int32 { return int32(len(e.entries)) }

// Remarks is the element's "remarks" (trimmed), or "" when it has none.
func (e *CoreConfigEntries) Remarks(index int32) string { return e.entries[index].remarks }

// Content is the element as an indented JSON object, keys in their original order.
func (e *CoreConfigEntries) Content(index int32) string { return e.entries[index].content }

// Core is the element's own detected core (xray, sing-box, ...).
func (e *CoreConfigEntries) Core(index int32) string { return e.entries[index].core }

// isCoreConfigArray reports whether text is a non-empty JSON array whose
// elements are all JSON objects.
func isCoreConfigArray(text string) bool {
	_, ok := coreConfigArrayElements(text)
	return ok
}

func coreConfigArrayElements(text string) ([]json.RawMessage, bool) {
	if !strings.HasPrefix(text, "[") {
		return nil, false
	}
	var elements []json.RawMessage
	if json.Unmarshal([]byte(text), &elements) != nil || len(elements) == 0 {
		return nil, false
	}
	for _, element := range elements {
		trimmed := bytes.TrimSpace(element)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, false
		}
	}
	return elements, true
}

// SplitCoreConfigArray splits a JSON array of configs into one entry per
// element, each with its own detected core. An array of Xray configs that
// differ only in one proxy outbound is merged into a single entry without
// remarks instead (mergeXrayConfigArray). Xray elements keep every key
// (Xray ignores unknown ones, and the kept "remarks" lets a subscription
// update find the same element again); sing-box rejects unknown keys, so
// "remarks" is removed from sing-box elements. Nothing else is converted.
func SplitCoreConfigArray(content string) (*CoreConfigEntries, error) {
	return splitCoreConfigArray(content, true)
}

// SplitCoreConfigArrayEach splits a JSON array of configs into exactly one
// entry per element, never merging: a subscription that serves several
// configs becomes one profile per config.
func SplitCoreConfigArrayEach(content string) (*CoreConfigEntries, error) {
	return splitCoreConfigArray(content, false)
}

func splitCoreConfigArray(content string, merge bool) (*CoreConfigEntries, error) {
	elements, ok := coreConfigArrayElements(normalizeCoreContent(content))
	if !ok {
		return nil, fmt.Errorf("not a JSON array of configs")
	}
	result := &CoreConfigEntries{}
	remarks := make([]string, len(elements))
	for index, element := range elements {
		remarks[index] = coreConfigRemarksOf(element)
	}
	// One node per element with everything else shared: one profile whose
	// nodes form a group (core_array_merge.go).
	if merge {
		if merged, ok := mergeXrayConfigArray(elements, remarks); ok {
			var indented bytes.Buffer
			if err := json.Indent(&indented, merged, "", "  "); err == nil {
				indented.WriteByte('\n')
				result.entries = append(result.entries, coreConfigEntry{content: indented.String(), core: CoreXray})
				return result, nil
			}
		}
	}
	for index, element := range elements {
		core := DetectCoreConfig(string(element))
		raw := []byte(element)
		if core == CoreSingBox {
			stripped, err := removeTopLevelKey(raw, "remarks")
			if err != nil {
				return nil, fmt.Errorf("config %d: %w", index+1, err)
			}
			raw = stripped
		}
		var indented bytes.Buffer
		if err := json.Indent(&indented, bytes.TrimSpace(raw), "", "  "); err != nil {
			return nil, fmt.Errorf("config %d: %w", index+1, err)
		}
		indented.WriteByte('\n')
		result.entries = append(result.entries, coreConfigEntry{remarks: remarks[index], content: indented.String(), core: core})
	}
	return result, nil
}

// CoreConfigRemarks returns the top-level "remarks" of a JSON object config,
// or "" when there is none.
func CoreConfigRemarks(content string) string {
	text := normalizeCoreContent(content)
	if !strings.HasPrefix(text, "{") {
		return ""
	}
	return coreConfigRemarksOf([]byte(text))
}

func coreConfigRemarksOf(raw []byte) string {
	var root struct {
		Remarks any `json:"remarks"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return ""
	}
	if remarks, ok := root.Remarks.(string); ok {
		return strings.TrimSpace(remarks)
	}
	return ""
}

// removeTopLevelKey re-emits a JSON object without key, keeping the order of
// the remaining keys and their values byte for byte.
func removeTopLevelKey(raw []byte, key string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("not a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
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
		if name == key {
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		encodedName, _ := json.Marshal(name)
		out.Write(encodedName)
		out.WriteByte(':')
		out.Write(value)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}
