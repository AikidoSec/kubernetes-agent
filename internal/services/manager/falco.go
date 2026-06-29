package manager

import (
	"context"
	"fmt"
	"os"
	"strings"

	"aikidoSec.kubernetesAgent/internal/falco"
	"aikidoSec.kubernetesAgent/pkg/models"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys in the kubernetes-agent-falco-config ConfigMap (mounted at /etc/falco/aikido-config.d/).
const (
	rulesOverrideKey = "rules-override.yaml"
)

// RegisterFalcoProxy injects the Falco event proxy into the manager (when threat detection is enabled).
func (s *Service) RegisterFalcoProxy(proxy *falco.Proxy) {
	s.falcoProxy = proxy
}

// rebuildFalcoRulesConfig writes the complete rules override to the Falco config ConfigMap.
// All rulesets are denied by default; only explicitly enabled rules fire.
// To add a new ruleset (e.g. SCA), read its state from agentState and append enables here.
func (s *Service) rebuildFalcoRulesConfig(ctx context.Context) error {
	cmName := s.GetFalcoConfigMapName()
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, cmName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco config configmap %q: %w", cmName, err)
	}

	overrideYAML, err := buildRulesOverrideYAML(s.GetEnabledThreatRules())
	if err != nil {
		return fmt.Errorf("error marshalling rules override: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[rulesOverrideKey] = overrideYAML

	if _, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Update(ctx, cm, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco config configmap %q: %w", cmName, err)
	}

	return nil
}

// buildRulesOverrideYAML produces the YAML content for the rules-override.yaml key in the
// kubernetes-agent-falco-config ConfigMap. It disables all rules globally and then re-enables
// each rule in enabledRules individually, which is the Falco config.d mechanism for allowlisting.
func buildRulesOverrideYAML(enabledRules []string) (string, error) {
	rulesActions := []models.FalcoRuleAction{{Disable: models.FalcoRuleSelector{Rule: "*"}}}
	for _, rule := range enabledRules {
		rulesActions = append(rulesActions, models.FalcoRuleAction{Enable: models.FalcoRuleSelector{Rule: rule}})
	}
	override := map[string]any{"rules": rulesActions}
	data, err := yaml.Marshal(override)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Service) rebuildFalcoExceptionsConfig(ctx context.Context) error {
	cmName := s.GetFalcoRulesConfigMapName()
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, cmName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco rules configmap %q: %w", cmName, err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[threatDetectionExceptionsKey] = buildExceptionsYAML(s.GetThreatDetectionExceptions())

	if _, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Update(ctx, cm, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco rules configmap %q: %w", cmName, err)
	}
	return nil
}

// falcoValueTuple marshals as a flow-style sequence (e.g. [myapp, default]).
// Each element is either a string (scalar operators) or []string (for the "in"
// operator), which becomes a nested flow-style sequence: [cat, [/etc/shadow, /etc/passwd]].
type falcoValueTuple []any

func (t falcoValueTuple) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, v := range t {
		switch val := v.(type) {
		case string:
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: val})
		case []string:
			inner := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
			for _, item := range val {
				inner.Content = append(inner.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: item})
			}
			node.Content = append(node.Content, inner)
		}
	}
	return node, nil
}

type falcoExceptionEntry struct {
	Name   string            `yaml:"name"`
	Fields []string          `yaml:"fields"`
	Comps  []string          `yaml:"comps"`
	Values []falcoValueTuple `yaml:"values"`
}

type falcoOverride struct {
	Exceptions string `yaml:"exceptions"`
}

type falcoRuleExceptionBlock struct {
	Rule       string                `yaml:"rule"`
	Exceptions []falcoExceptionEntry `yaml:"exceptions"`
	Override   falcoOverride         `yaml:"override"`
}

// parseInValues parses a comma-separated value list for the "in" operator,
// trimming whitespace and skipping empty entries. Returns nil if all entries are empty.
func parseInValues(raw string) []string {
	parts := strings.Split(raw, ",")
	trimmed := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			trimmed = append(trimmed, v)
		}
	}
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}

func buildExceptionsYAML(exceptions []models.ThreatDetectionException) string {
	// Group exceptions by rule name so each rule gets one override block.
	byRule := make(map[string][]falcoExceptionEntry)
	ruleOrder := make([]string, 0)
	for _, exc := range exceptions {
		entry := falcoExceptionEntry{
			// Falco requires exception names to be unique per rule. Prefixing with the DB ID
			// guarantees uniqueness even when two exceptions share the same user-facing name.
			Name: fmt.Sprintf("%d: %s", exc.ID, exc.Name),
		}
		for _, c := range exc.Conditions {
			entry.Fields = append(entry.Fields, c.Field)
			entry.Comps = append(entry.Comps, c.Operator)
		}
		tuple := make(falcoValueTuple, len(exc.Conditions))
		skip := false
		for i, c := range exc.Conditions {
			if c.Operator == "in" {
				values := parseInValues(c.Value)
				if values == nil {
					skip = true
					break
				}
				tuple[i] = values
			} else {
				tuple[i] = c.Value
			}
		}
		if skip {
			continue
		}
		entry.Values = []falcoValueTuple{tuple}

		for _, ruleName := range exc.RuleNames {
			if _, seen := byRule[ruleName]; !seen {
				ruleOrder = append(ruleOrder, ruleName)
			}
			byRule[ruleName] = append(byRule[ruleName], entry)
		}
	}

	if len(byRule) == 0 {
		return ""
	}

	blocks := make([]falcoRuleExceptionBlock, 0, len(byRule))
	for _, ruleName := range ruleOrder {
		blocks = append(blocks, falcoRuleExceptionBlock{
			Rule:       ruleName,
			Exceptions: byRule[ruleName],
			Override:   falcoOverride{Exceptions: "append"},
		})
	}

	data, err := yaml.Marshal(blocks)
	if err != nil {
		return ""
	}
	return string(data)
}

// UpdateFalcoVersion updates all containers and init containers in the Falco DaemonSet to the new version.
// Both are patched because some driver modes use an init container for driver loading.
func (s *Service) UpdateFalcoVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetFalcoDaemonSetName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco daemonset: %w", err)
	}

	for i, container := range daemonSet.Spec.Template.Spec.Containers {
		daemonSet.Spec.Template.Spec.Containers[i].Image = updateImageTag(container.Image, newVersion)
	}

	for i, container := range daemonSet.Spec.Template.Spec.InitContainers {
		daemonSet.Spec.Template.Spec.InitContainers[i].Image = updateImageTag(container.Image, newVersion)
	}

	daemonSet.Labels["app.kubernetes.io/version"] = newVersion
	daemonSet.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, daemonSet, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco daemonset: %w", err)
	}

	s.SetFalcoVersion(newVersion)
	return nil
}

// updateImageTag rewrites the tag portion of a tagged image reference like
// "falcosecurity/falco:0.43.0". Untagged references are returned unchanged.
// Digest-pinned references are not handled yet — revisit when the heartbeat
// payload starts carrying digests.
func updateImageTag(image, newTag string) string {
	lastColon := strings.LastIndex(image, ":")
	lastSlash := strings.LastIndex(image, "/")
	if lastColon <= lastSlash {
		return image
	}
	return image[:lastColon] + ":" + newTag
}
