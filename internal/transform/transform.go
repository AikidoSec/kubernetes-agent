// Package transform rewrites Kubernetes labels and annotations in marshalled asset payloads.
package transform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"aikidoSec.kubernetesAgent/pkg/models"
)

// wildcard in a metadata path stands for every element of the JSON array at the preceding key.
const wildcard = "*"

// metadataPaths are the locations of ObjectMeta blocks that carry labels and annotations.
var metadataPaths = [][]string{
	{"metadata"},
	{"spec", "template", "metadata"},
	{"spec", "jobTemplate", "metadata"},
	{"spec", "jobTemplate", "spec", "template", "metadata"},
	{"spec", "jobTargetRef", "template", "metadata"},
	{"spec", "metadata"},
	{"spec", "strategy", "canary", "canaryMetadata"},
	{"spec", "strategy", "canary", "stableMetadata"},
	{"spec", "strategy", "blueGreen", "previewMetadata"},
	{"spec", "strategy", "blueGreen", "activeMetadata"},
	{"spec", "strategy", "canary", "steps", wildcard, "experiment", "templates", wildcard, "metadata"},
}

// redactedLength is the number of hex characters of the SHA-256 digest kept for a redacted value.
const redactedLength = 32

// Transformer applies label and annotation rules while marshalling. A nil Transformer is a plain json.Marshal.
type Transformer struct {
	labels      map[string]models.KeyRule
	annotations map[string]models.KeyRule
}

// New returns nil when no rules are configured.
func New(rules models.MetadataTransforms) *Transformer {
	if rules.IsEmpty() {
		return nil
	}
	return &Transformer{labels: rules.Labels, annotations: rules.Annotations}
}

// Marshal encodes obj as JSON with the configured rules applied. obj is never modified.
func (t *Transformer) Marshal(obj any) ([]byte, error) {
	if t == nil {
		return json.Marshal(obj)
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return raw, nil
	}

	changed := false
	for _, path := range metadataPaths {
		if t.rewrite(root, path) {
			changed = true
		}
	}
	if t.rewriteServiceSelector(root) {
		changed = true
	}
	if t.rewriteWorkloadSelector(root) {
		changed = true
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(root)
}

// rewriteServiceSelector applies the label rules to the selector of a core/v1 Service so it keeps matching the rewritten pod labels.
func (t *Transformer) rewriteServiceSelector(root map[string]json.RawMessage) bool {
	if len(t.labels) == 0 || !isCoreService(root) {
		return false
	}
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(root["spec"], &spec); err != nil || spec == nil {
		return false
	}
	if !t.rewriteStringMap(spec, "selector", t.labels) {
		return false
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return false
	}
	root["spec"] = encoded
	return true
}

// rewriteWorkloadSelector applies the label rules to `spec.selector.matchLabels` so a workload selector keeps matching its rewritten template labels.
func (t *Transformer) rewriteWorkloadSelector(root map[string]json.RawMessage) bool {
	if len(t.labels) == 0 || isCoreService(root) {
		return false
	}
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(root["spec"], &spec); err != nil || spec == nil {
		return false
	}
	var selector map[string]json.RawMessage
	if err := json.Unmarshal(spec["selector"], &selector); err != nil || selector == nil {
		return false
	}
	if !t.rewriteStringMap(selector, "matchLabels", t.labels) {
		return false
	}
	encodedSelector, err := json.Marshal(selector)
	if err != nil {
		return false
	}
	spec["selector"] = encodedSelector
	encodedSpec, err := json.Marshal(spec)
	if err != nil {
		return false
	}
	root["spec"] = encodedSpec
	return true
}

func isCoreService(root map[string]json.RawMessage) bool {
	return stringField(root, "apiVersion") == "v1" && stringField(root, "kind") == "Service"
}

func stringField(node map[string]json.RawMessage, field string) string {
	var value string
	if err := json.Unmarshal(node[field], &value); err != nil {
		return ""
	}
	return value
}

func redact(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:redactedLength]
}

func (t *Transformer) rewrite(node map[string]json.RawMessage, path []string) bool {
	child, ok := node[path[0]]
	if !ok {
		return false
	}
	if len(path) > 1 && path[1] == wildcard {
		return t.rewriteEach(node, path[0], child, path[2:])
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(child, &obj); err != nil || obj == nil {
		return false
	}

	var changed bool
	if len(path) == 1 {
		changed = t.rewriteStringMap(obj, "labels", t.labels)
		if t.rewriteStringMap(obj, "annotations", t.annotations) {
			changed = true
		}
	} else {
		changed = t.rewrite(obj, path[1:])
	}
	if !changed {
		return false
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		return false
	}
	node[path[0]] = encoded
	return true
}

func (t *Transformer) rewriteEach(node map[string]json.RawMessage, key string, array json.RawMessage, rest []string) bool {
	var items []json.RawMessage
	if err := json.Unmarshal(array, &items); err != nil {
		return false
	}
	changed := false
	for i, item := range items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil || obj == nil || !t.rewrite(obj, rest) {
			continue
		}
		encoded, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		items[i] = encoded
		changed = true
	}
	if !changed {
		return false
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return false
	}
	node[key] = encoded
	return true
}

func (t *Transformer) rewriteStringMap(meta map[string]json.RawMessage, field string, rules map[string]models.KeyRule) bool {
	if len(rules) == 0 {
		return false
	}
	var values map[string]string
	if err := json.Unmarshal(meta[field], &values); err != nil || len(values) == 0 {
		return false
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]string, len(values))
	renamed := make(map[string]string)
	changed := false
	for _, key := range keys {
		rule, ok := rules[key]
		if !ok {
			result[key] = values[key]
			continue
		}
		changed = true
		value := values[key]
		if mapped, ok := rule.ValueMap[value]; ok {
			value = mapped
		}
		if rule.Redact {
			value = redact(value)
		}
		if rule.Rename != nil {
			renamed[*rule.Rename] = value
		} else {
			result[key] = value
		}
	}
	for k, v := range renamed {
		result[k] = v
	}
	if !changed {
		return false
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return false
	}
	meta[field] = encoded
	return true
}
