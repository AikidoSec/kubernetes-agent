package manager

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"aikidoSec.kubernetesAgent/internal/falco"
	"aikidoSec.kubernetesAgent/pkg/models"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys in the kubernetes-agent-falco-rules ConfigMap (mounted at /etc/falco/rules.d/).
const (
	threatDetectionRulesKey      = "01-threat-detection-rules.yaml"
	threatDetectionExceptionsKey = "02-threat-detection-exceptions.yaml"
)

// Keys in the kubernetes-agent-falco-config ConfigMap (mounted at /etc/falco/aikido-config.d/).
const (
	rulesOverrideKey = "rules-override.yaml"
)

// RegisterFalcoProxy injects the Falco event proxy into the manager (when threat detection is enabled).
func (s *Service) RegisterFalcoProxy(proxy *falco.Proxy) {
	s.falcoProxy = proxy
}

func (s *Service) handleThreatDetectionHeartbeat(ctx context.Context, td models.ThreatDetectionHeartbeat) {
	wasEnabled := s.IsThreatDetectionEnabled()
	nowEnabled := td.Enabled

	if wasEnabled != nowEnabled {
		s.logger.LogInfo("threat detection enabled changed from heartbeat response", "enabled", nowEnabled)
		s.SetThreatDetectionEnabled(nowEnabled)
	}

	if !s.IsChartsRuntimeDetectionEnabled() {
		return
	}

	if !wasEnabled && nowEnabled {
		// Enabling: write the embedded rules file; the block below handles config rebuild and restart.
		falcoVersion, err := loadDaemonSetVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetThreatDetectorDaemonSetName())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading falco version from daemonset", "managerError")
		}
		s.SetFalcoVersion(falcoVersion)
		if err := s.WriteEmbeddedThreatRules(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error writing embedded threat rules to configmap", "managerError")
		}
	}

	if wasEnabled && !nowEnabled {
		// Disabling: clear both rule files so Falco doesn't try to append exceptions to rules that no longer exist.
		s.SetFalcoVersion("")
		s.SetEnabledThreatRules([]string{})
		if err := s.ClearEmbeddedThreatRules(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error clearing embedded threat rules from configmap", "managerError")
		}
		s.SetThreatDetectionExceptions([]models.ThreatDetectionException{})
		if err := s.rebuildFalcoExceptionsConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error clearing threat detection exceptions from configmap", "managerError")
		}
		if err := s.restartDaemonSet(ctx, s.GetThreatDetectorDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
		return
	}

	if !nowEnabled {
		return
	}

	newEnabledRules := td.Rules
	// null means the server could not load exceptions — keep current state unchanged.
	newExceptions := td.Exceptions

	rulesChanged := !slices.Equal(s.GetEnabledThreatRules(), newEnabledRules)
	exceptionsChanged := newExceptions != nil && !slices.EqualFunc(s.GetThreatDetectionExceptions(), *newExceptions, models.ThreatDetectionExceptionEqual)

	if rulesChanged {
		s.logger.LogInfo("threat detection rules changed from heartbeat response", "current rules", s.GetEnabledThreatRules(), "new rules", newEnabledRules)
		if err := s.UpdateEnabledThreatRules(ctx, newEnabledRules); err != nil {
			s.logger.ReportError(ctx, err, "error updating enabled threat detection rules", "managerError")
		}
	}

	if exceptionsChanged {
		s.logger.LogInfo("threat detection exceptions changed from heartbeat response")
		s.SetThreatDetectionExceptions(*newExceptions)
		if err := s.rebuildFalcoExceptionsConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error updating threat detection exceptions", "managerError")
		}
	}

	if rulesChanged || exceptionsChanged {
		if err := s.restartDaemonSet(ctx, s.GetThreatDetectorDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
	}
}

func (s *Service) UpdateEnabledThreatRules(ctx context.Context, enabledRules []string) error {
	s.SetEnabledThreatRules(enabledRules)
	return s.rebuildFalcoRulesConfig(ctx)
}

// rebuildFalcoRulesConfig writes the complete rules override to the runtime detection ConfigMap.
// All rulesets are denied by default; only explicitly enabled rules fire.
// To add a new ruleset (e.g. SCA), read its state from agentState and append enables here.
func (s *Service) rebuildFalcoRulesConfig(ctx context.Context) error {
	cmName := s.GetRuntimeDetectionConfigMapName()
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, cmName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting runtime detection configmap %q: %w", cmName, err)
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
		return fmt.Errorf("error updating runtime detection configmap %q: %w", cmName, err)
	}

	return nil
}

// buildRulesOverrideYAML produces the YAML content for the rules-override.yaml key in the
// kubernetes-agent-falco-config ConfigMap. It disables all rules globally and then re-enables
// each rule in enabledRules individually, which is the Falco config.d mechanism for allowlisting.
func buildRulesOverrideYAML(enabledRules []string) (string, error) {
	rulesActions := []models.ThreatRuleAction{{Disable: models.ThreatRuleSelector{Rule: "*"}}}
	for _, rule := range enabledRules {
		rulesActions = append(rulesActions, models.ThreatRuleAction{Enable: models.ThreatRuleSelector{Rule: rule}})
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

func (s *Service) WriteEmbeddedThreatRules(ctx context.Context) error {
	cmName := s.GetFalcoRulesConfigMapName()
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, cmName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco rules configmap %q: %w", cmName, err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[threatDetectionRulesKey] = string(falco.EmbeddedThreatRules)

	if _, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Update(ctx, cm, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco rules configmap %q: %w", cmName, err)
	}
	return nil
}

func (s *Service) ClearEmbeddedThreatRules(ctx context.Context) error {
	cmName := s.GetFalcoRulesConfigMapName()
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, cmName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco rules configmap %q: %w", cmName, err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[threatDetectionRulesKey] = ""

	if _, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Update(ctx, cm, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco rules configmap %q: %w", cmName, err)
	}
	return nil
}

// UpdateFalcoVersion updates all containers and init containers in the Falco DaemonSet to the new version.
// Both are patched because some driver modes use an init container for driver loading.
func (s *Service) UpdateFalcoVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetThreatDetectorDaemonSetName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting falco daemonset: %w", err)
	}

	for i, container := range daemonSet.Spec.Template.Spec.Containers {
		if updated, ok := updateImageTag(container.Image, newVersion); ok {
			daemonSet.Spec.Template.Spec.Containers[i].Image = updated
		} else {
			s.logger.LogWarning(nil, "skipping falco container image update: digest-pinned or untagged reference", "image", container.Image)
		}
	}

	for i, container := range daemonSet.Spec.Template.Spec.InitContainers {
		if updated, ok := updateImageTag(container.Image, newVersion); ok {
			daemonSet.Spec.Template.Spec.InitContainers[i].Image = updated
		} else {
			s.logger.LogWarning(nil, "skipping falco init container image update: digest-pinned or untagged reference", "image", container.Image)
		}
	}

	daemonSet.Labels["app.kubernetes.io/version"] = newVersion
	daemonSet.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, daemonSet, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating falco daemonset: %w", err)
	}

	s.SetFalcoVersion(newVersion)
	return nil
}

// updateImageTag rewrites the tag portion of an image reference. Returns ok=false
// for digest-pinned references (containing '@'): rewriting only the tag while keeping
// the original digest would leave the image effectively pinned to the old version
// (Kubernetes pulls by digest), silently breaking the version update. Once the heartbeat
// payload carries both a tag and a digest, this guard can be relaxed to update both together.
// Returns ok=false when no tag is present (e.g. "registry:5000/org/img"), since we don't
// invent tags out of nothing.
func updateImageTag(image, newTag string) (string, bool) {
	if strings.Contains(image, "@") {
		return "", false
	}
	lastColon := strings.LastIndex(image, ":")
	lastSlash := strings.LastIndex(image, "/")
	if lastColon <= lastSlash {
		return "", false
	}
	return image[:lastColon] + ":" + newTag, true
}
