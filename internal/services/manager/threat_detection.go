package manager

import (
	"context"
	"fmt"
	"slices"

	"aikidoSec.kubernetesAgent/internal/falco"
	"aikidoSec.kubernetesAgent/pkg/models"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys in the kubernetes-agent-falco-rules ConfigMap (mounted at /etc/falco/rules.d/).
const (
	threatDetectionRulesKey      = "01-threat-detection-rules.yaml"
	threatDetectionExceptionsKey = "02-threat-detection-exceptions.yaml"
)

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
		falcoVersion, err := loadDaemonSetVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetFalcoDaemonSetName())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading falco version from daemonset", "managerError")
		}
		s.SetFalcoVersion(falcoVersion)
		if err := s.WriteEmbeddedThreatRules(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error writing embedded threat rules to configmap", "managerError")
		}
	}

	if wasEnabled && !nowEnabled {
		// Disabling: clear in-memory state and rebuild all three ConfigMap files so they end up
		// in a known-empty state.
		s.SetFalcoVersion("")
		s.SetEnabledThreatRules([]string{})
		if err := s.ClearEmbeddedThreatRules(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error clearing embedded threat rules from configmap", "managerError")
		}
		if err := s.rebuildFalcoRulesConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error clearing threat detection rules override from configmap", "managerError")
		}
		s.SetThreatDetectionExceptions([]models.ThreatDetectionException{})
		if err := s.rebuildFalcoExceptionsConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error clearing threat detection exceptions from configmap", "managerError")
		}
		if err := s.restartDaemonSet(ctx, s.GetFalcoDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
		return
	}

	if !nowEnabled {
		return
	}

	// null means the server could not load rules/exceptions — keep current state unchanged.
	newEnabledRules := td.Rules
	newExceptions := td.Exceptions

	rulesChanged := rulesChangedFromHeartbeat(s.GetEnabledThreatRules(), newEnabledRules)
	exceptionsChanged := exceptionsChangedFromHeartbeat(s.GetThreatDetectionExceptions(), newExceptions)

	if rulesChanged {
		s.logger.LogInfo("threat detection rules changed from heartbeat response", "current rules", s.GetEnabledThreatRules(), "new rules", *newEnabledRules)
		if err := s.UpdateEnabledThreatRules(ctx, *newEnabledRules); err != nil {
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
		if err := s.restartDaemonSet(ctx, s.GetFalcoDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
	}
}

func (s *Service) UpdateEnabledThreatRules(ctx context.Context, enabledRules []string) error {
	s.SetEnabledThreatRules(enabledRules)
	return s.rebuildFalcoRulesConfig(ctx)
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

// rulesChangedFromHeartbeat decides whether the enabled-rules list should be rewritten.
// next == nil means the server couldn't load rules this beat — keep current state.
// Otherwise rewrite only if the lists differ.
func rulesChangedFromHeartbeat(current []string, next *[]string) bool {
	if next == nil {
		return false
	}
	return !slices.Equal(current, *next)
}

// exceptionsChangedFromHeartbeat decides whether the exceptions list should be rewritten.
// next == nil means the server couldn't load exceptions this beat — keep current state.
// Otherwise rewrite only if the lists differ.
func exceptionsChangedFromHeartbeat(current []models.ThreatDetectionException, next *[]models.ThreatDetectionException) bool {
	if next == nil {
		return false
	}
	return !slices.EqualFunc(current, *next, models.ThreatDetectionExceptionEqual)
}
