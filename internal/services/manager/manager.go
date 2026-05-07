package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/controllers/openshift"
	"aikidoSec.kubernetesAgent/internal/falco"
	internalhttp "aikidoSec.kubernetesAgent/internal/http"
	httpcontrollers "aikidoSec.kubernetesAgent/internal/http/controllers"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/sbom"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/imagescache"
	"aikidoSec.kubernetesAgent/pkg/models"
	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/google/uuid"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var noHostErrorMessage = "no such host"

const (
	defaultAgentVersion = "1.0.0"
)

var ignoredEventsReasons = []string{
	"Pulled",
	"Created",
	"Started",
	"Scheduled",
	"ScalingReplicaSet",
	"SuccessfulCreate",
	"SuccessfulDelete",
}

type Options struct {
	AgentNamespace                    string
	AgentName                         string
	APIToken                          string
	APIEndpoint                       string
	ConfigSecretName                  string
	AgentPodName                      string
	ExcludedNamespaces                []string
	HeartbeatService                  *heartbeat.Service
	AssetsOutputClient                *batchclient.BatchClient
	Logger                            *logger.Service
	ControllerCacheSyncTimeout        time.Duration
	IsSBOMCollectorRunningAsDaemonSet bool
	AutoUpdateEnabled                 bool
}
type Service struct {
	*models.AgentState
	scannedImagesCache *imagescache.ImagesCache
	logger             *logger.Service
	// Channel to stop the heartbeat goroutine.
	heartbeatStopChan   chan struct{}
	kubernetesClientSet *kubernetes.Clientset
	heartbeatService    *heartbeat.Service
	assetsOutputClient  *batchclient.BatchClient
	falcoProxy          *falco.Proxy
	metricClient        *metricsclient.Clientset
}

func NewService(ctx context.Context, agentState *models.AgentState, o Options) (*Service, error) {
	ctrlConfig, err := ctrlconfig.GetConfig()
	if err != nil {
		o.Logger.ReportError(ctx, err, "error getting kubeconfig", "managerError")
		return nil, fmt.Errorf("error getting kubeconfig: %w", err)
	}

	clientSet, err := kubernetes.NewForConfig(ctrlConfig)
	if err != nil {
		o.Logger.ReportError(ctx, err, "error getting kubernetes clientSet", "managerError")
		return nil, fmt.Errorf("error creating kubernetes client: %w", err)
	}

	// Initialize the agent state with all values from options and context
	agentState.SetInitialValues(
		o.AgentPodName,
		o.AgentNamespace,
		o.AgentName,
		o.APIToken,
		o.APIEndpoint,
		o.ConfigSecretName,
		o.ControllerCacheSyncTimeout,
		o.IsSBOMCollectorRunningAsDaemonSet,
		fmt.Sprintf("%s-sbom-collector", o.AgentName),
		o.AutoUpdateEnabled,
		fmt.Sprintf("%s-runtime-protection", o.AgentName),
	)

	// Build the cluster configuration based on the environment.
	var cfg *rest.Config
	if IsLocalEnvironment() {
		cfg, err = BuildLocalConfig()
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		o.Logger.LogInfo("unable to use in-cluster config, memory usage reporting will be disabled", "error", err.Error())
	}

	var mClient *metricsclient.Clientset
	if cfg != nil {
		// Create the metrics client
		mClient, err = metricsclient.NewForConfig(cfg)
		if err != nil {
			o.Logger.LogInfo("unable to create metrics client, memory usage reporting will be disabled", "error", err.Error())
			mClient = nil
		}
	}

	return &Service{
		AgentState:          agentState,
		heartbeatStopChan:   make(chan struct{}),
		kubernetesClientSet: clientSet,
		heartbeatService:    o.HeartbeatService,
		logger:              o.Logger,
		assetsOutputClient:  o.AssetsOutputClient,
		metricClient:        mClient,
		scannedImagesCache:  imagescache.NewImagesCache(),
	}, nil
}

const (
	threatDetectionRulesKey      = "01-threat-detection-rules.yaml"
	threatDetectionExceptionsKey = "02-threat-detection-exceptions.yaml"
)

func (s *Service) StartHeartbeat() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.LogError(fmt.Errorf("panic recovered: %v", r), "panic recovered in periodic heartbeat")
		}
	}()

	s.heartbeatStopChan = make(chan struct{})
	ticker := time.NewTicker(s.heartbeatService.GetSendInterval())
	go func() {
		for {
			select {
			case <-ticker.C:
				ctx := context.Background()
				_, _ = s.SendHeartbeat(ctx)
			case <-s.heartbeatStopChan:
				close(s.heartbeatStopChan)
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Service) StopHeartbeat() {
	s.heartbeatStopChan <- struct{}{}
}

func (s *Service) Close(ctx context.Context) {
	s.StopHeartbeat()

	if err := s.assetsOutputClient.Close(ctx); err != nil {
		s.logger.ReportError(ctx, err, "error closing assets output client", "managerError")
	}
}

// SendHeartbeat sends a heartbeat to the management server and processes the response
func (s *Service) SendHeartbeat(ctx context.Context) (models.HeartbeatResponse, error) {
	metrics := models.Metrics{}
	if s.metricClient != nil {
		agentMetrics, _ := s.GetAgentMetrics(ctx)
		// We currently ignore the errors since most agents will lack the necessary permissions to fetch metrics.
		metrics.AgentMetrics = agentMetrics
	}

	metricsPayload, err := json.Marshal(metrics)
	if err != nil {
		s.logger.ReportError(ctx, err, "error marshalling metrics payload", "managerError")
	}

	// Load the agent and charts versions from the deployment labels. We don't use the agent state value here because the version
	// might have been updated in the deployment but the new pod might fail to schedule or start, so we need to know if
	// the old pod is the one that sends the heartbeat.
	// Also, the charts can be updated without triggering a deployment update, so we need to load it every time.
	agentVersion, helmChartsVersion, err := s.GetDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context at heartbeat", "managerError")
	}

	sbomCollectorVersion := s.GetSBOMCollectorVersion()
	if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err = LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		}
	}

	falcoVersion := s.GetFalcoVersion()
	if s.IsChartsThreatDetectionEnabled() && s.IsThreatDetectionEnabled() {
		falcoVersion, err = LoadDaemonSetVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetThreatDetectorDaemonSetName())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading falco version from daemonset", "managerError")
		}
	}

	resp, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       agentVersion,
		CollectorVersion:   sbomCollectorVersion,
		FalcoVersion:       falcoVersion,
		IsInitialHeartbeat: false,
		Metrics:            string(metricsPayload),
		HelmChartsVersion:  helmChartsVersion,
		AgentPodName:       s.GetAgentPodName(),
		AgentNamespace:     s.GetAgentNamespace(),
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending heartbeat", "managerError")
		return models.HeartbeatResponse{}, err
	}

	// If the token has changed, update it in the service, output clients and in the agent Kubernetes secret
	if s.GetAPIToken() != resp.Token && resp.Token != "" {
		s.logger.LogInfo("API token updated from heartbeat response")
		if err := s.UpdateAPIToken(ctx, resp.Token); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent API token", "managerError")
			return resp, err
		}
	}

	if s.GetAutoUpdateEnabled() {
		// If the agent version has changed, update the deployment with the new image version which will also trigger a restart
		if s.GetAgentVersion() != resp.Cluster.DesiredAgentVersion {
			s.logger.LogInfo("agent version updated from heartbeat response", "current version", s.GetAgentVersion(), "new version", resp.Cluster.DesiredAgentVersion)
			if err := s.UpdateAgentVersion(ctx, resp.Cluster.DesiredAgentVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating agent version", "managerError")
				return resp, err
			}
			s.SetAgentVersion(resp.Cluster.DesiredAgentVersion)
		}
	}

	// If the namespace filter has changed, restart the agent to re-create the watchers with the new filters
	excludedChanged := !slices.Equal(s.GetExcludedNamespaces(), resp.Cluster.ExcludedNamespaces)
	includedChanged := !slices.Equal(s.GetIncludedNamespaces(), resp.Cluster.IncludedNamespaces)
	if excludedChanged || includedChanged {
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			s.logger.LogInfo("namespace filter changed, restarting sbom collector")
			if err := s.RestartSBOMCollector(ctx); err != nil {
				s.logger.ReportError(ctx, err, "error restarting sbom collector", "managerError")
			}
		}

		s.logger.LogInfo("namespace filter changed, restarting agent")
		if err := s.RestartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetExcludedNamespaces(resp.Cluster.ExcludedNamespaces)
		s.SetIncludedNamespaces(resp.Cluster.IncludedNamespaces)
	}

	monitoredResourcesGVKs := make([]string, 0, len(resp.MonitoredResources))
	for _, gvk := range resp.MonitoredResources {
		monitoredResourcesGVKs = append(monitoredResourcesGVKs, gvk.String())
	}

	// If the monitored resources have changed, restart the agent to re-create the watchers with the new configuration
	if !slices.Equal(s.GetMonitoredResources(), monitoredResourcesGVKs) {
		s.logger.LogInfo("monitored resources changed, restarting agent")
		if err := s.RestartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetMonitoredResources(monitoredResourcesGVKs)
	}

	// If the SBOM collector enabled state has changed, update the deployment/daemonset accordingly
	if s.IsSBOMCollectorEnabled() != resp.Cluster.SBOMCollectorEnabled {
		s.logger.LogInfo("sbom collector enabled state changed from heartbeat response", "current state", s.IsSBOMCollectorEnabled(), "new state", resp.Cluster.SBOMCollectorEnabled)
		if err := s.ConfigureSBOMCollector(ctx, resp.Cluster.SBOMCollectorEnabled, s.IsChartsSBOMCollectorEnabled()); err != nil {
			s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
			return resp, err
		}
		s.SetSBOMCollectorEnabled(resp.Cluster.SBOMCollectorEnabled)

		// If the SBOM collector was enabled, load the scanned images from the API server into the cache and set the deployed collector version.
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			// Load the SBOM collector version from the deployment labels
			sbomCollectorVersion, err := LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
			if err != nil {
				s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
			}
			s.SetSBOMCollectorVersion(sbomCollectorVersion)
			// Load the scanned images cache
			collectorScannedImages, err := s.ListCollectorScannedImages(ctx)
			if err != nil {
				s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
			}

			if len(collectorScannedImages) > 0 {
				s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
			}
		} else {
			// If the SBOM collector was disabled, clear the collector deployed version.
			s.SetSBOMCollectorVersion("")
		}
	}

	if s.GetAutoUpdateEnabled() {
		// If the SBOM collector version has changed, update it in the service state
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() && s.GetSBOMCollectorVersion() != resp.Cluster.DesiredSBOMCollectorVersion {
			s.logger.LogInfo("sbom collector version updated from heartbeat response", "current version", s.GetSBOMCollectorVersion(), "new version", resp.Cluster.DesiredSBOMCollectorVersion)
			if err := s.UpdateSBOMCollectorVersion(ctx, resp.Cluster.DesiredSBOMCollectorVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating sbom collector version", "managerError")
			}
			s.SetSBOMCollectorVersion(resp.Cluster.DesiredSBOMCollectorVersion)
		}
	}

	// In case no hash is being received through the heartbeat, assume the cache has not changed to prevent pulling the cache from the cloud after every heartbeat
	if s.IsSBOMCollectorEnabled() && resp.ImageCacheHash != nil {
		if hash, err := s.scannedImagesCache.CalculateHash(); err != nil {
			s.logger.ReportError(ctx, err, "error calculating cache hash", "managerError")
		} else if hash != *resp.ImageCacheHash {
			collectorScannedImages, err := s.ListCollectorScannedImages(ctx)
			if err != nil {
				s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
			} else {
				s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
			}
		}
	}

	threatDetectionChanged := s.IsThreatDetectionEnabled() != resp.Cluster.ThreatDetectionEnabled
	if threatDetectionChanged {
		s.logger.LogInfo("threat detection enabled changed from heartbeat response", "enabled", resp.Cluster.ThreatDetectionEnabled)
		s.SetThreatDetectionEnabled(resp.Cluster.ThreatDetectionEnabled)

		if s.IsThreatDetectionEnabled() && s.IsChartsThreatDetectionEnabled() {
			falcoVersion, err := LoadDaemonSetVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetThreatDetectorDaemonSetName())
			if err != nil {
				s.logger.ReportError(ctx, err, "error loading falco version from daemonset", "managerError")
			}
			s.SetFalcoVersion(falcoVersion)
			if err := s.WriteEmbeddedThreatRules(ctx); err != nil {
				s.logger.ReportError(ctx, err, "error writing embedded threat rules to configmap", "managerError")
			}
		} else {
			s.SetFalcoVersion("")
			if err := s.ClearEmbeddedThreatRules(ctx); err != nil {
				s.logger.ReportError(ctx, err, "error clearing embedded threat rules from configmap", "managerError")
			}
		}
	}

	newEnabledRules := resp.EnabledThreatRules
	// null means the server could not load exceptions — keep current state unchanged.
	newExceptions := resp.ThreatDetectionExceptions
	if !s.IsThreatDetectionEnabled() {
		newEnabledRules = []string{}
		// Leave exceptions unchanged when disabling — Falco is shutting down anyway
		// and clearing exceptions before the DaemonSet stops creates an unnecessary window.
		newExceptions = nil
	}

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
		if err := s.RestartDaemonSet(ctx, s.GetThreatDetectorDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
	}

	if s.GetAutoUpdateEnabled() {
		if s.IsChartsThreatDetectionEnabled() && s.IsThreatDetectionEnabled() && s.GetFalcoVersion() != resp.Cluster.DesiredFalcoVersion {
			s.logger.LogInfo("falco version updated from heartbeat response", "current version", s.GetFalcoVersion(), "new version", resp.Cluster.DesiredFalcoVersion)
			if err := s.UpdateFalcoVersion(ctx, resp.Cluster.DesiredFalcoVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating falco version", "managerError")
			} else {
				s.SetFalcoVersion(resp.Cluster.DesiredFalcoVersion)
			}
		}
	}

	return resp, nil
}

func (s *Service) UpdateEnabledThreatRules(ctx context.Context, enabledRules []string) error {
	s.SetEnabledThreatRules(enabledRules)
	return s.rebuildFalcoRulesConfig(ctx)
}

// rebuildFalcoRulesConfig writes the complete rules override to the Falco ConfigMap from all
// current ruleset states. All rulesets are denied by default; only explicitly enabled rules fire.
// To add a new ruleset (e.g. SCA), read its state from agentState and append enables here.
func (s *Service) rebuildFalcoRulesConfig(ctx context.Context) error {
	cm, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Get(ctx, s.GetThreatDetectorDaemonSetName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting Threat Detector configmap: %w", err)
	}

	data := make(map[string]any)
	if err := yaml.Unmarshal([]byte(cm.Data["falco.yaml"]), &data); err != nil {
		return fmt.Errorf("error unmarshalling Threat Detector configmap: %w", err)
	}

	rulesActions := []models.ThreatRuleAction{{Disable: models.ThreatRuleSelector{Rule: "*"}}}
	for _, rule := range s.GetEnabledThreatRules() {
		rulesActions = append(rulesActions, models.ThreatRuleAction{Enable: models.ThreatRuleSelector{Rule: rule}})
	}

	data["rules"] = rulesActions
	newYaml, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling Threat Detector configmap: %w", err)
	}
	cm.Data["falco.yaml"] = string(newYaml)

	if _, err := s.kubernetesClientSet.CoreV1().ConfigMaps(s.GetAgentNamespace()).Update(ctx, cm, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating Threat Detector configmap: %w", err)
	}

	return nil
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

func buildExceptionsYAML(exceptions []models.ThreatDetectionException) string {
	// Group exceptions by rule name so each rule gets one override block.
	byRule := make(map[string][]falcoExceptionEntry)
	ruleOrder := make([]string, 0)
	for _, exc := range exceptions {
		entry := falcoExceptionEntry{
			Name: exc.Name,
		}
		for _, c := range exc.Conditions {
			entry.Fields = append(entry.Fields, c.Field)
			entry.Comps = append(entry.Comps, c.Operator)
		}
		tuple := make(falcoValueTuple, len(exc.Conditions))
		skip := false
		for i, c := range exc.Conditions {
			if c.Operator == "in" {
				parts := strings.Split(c.Value, ",")
				trimmed := make([]string, 0, len(parts))
				for _, p := range parts {
					if v := strings.TrimSpace(p); v != "" {
						trimmed = append(trimmed, v)
					}
				}
				if len(trimmed) == 0 {
					skip = true
					break
				}
				tuple[i] = trimmed
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

func (s *Service) InitializeAgent(ctx context.Context, cfg models.Config, runtimeManager manager.Manager, environmentConfig models.EnvironmentConfig) error {
	// Load the agent and charts versions from the deployment labels
	agentVersion, helmChartsVersion, err := s.GetDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context", "managerError")
		return fmt.Errorf("error loading agent version from context: %w", err)
	}
	s.SetAgentVersion(agentVersion)

	clusterIdentifier, err := s.GetClusterIdentifier(ctx)
	if err != nil {
		s.logger.LogWarning(err, "error getting cluster identifier", "managerError")
	}

	// List all events from the agent namespace.
	namespaceEvents, _ := s.ListEventsByFieldSelector(ctx, "")
	if namespaceEvents == nil {
		namespaceEvents = []corev1.Event{} // empty slice instead of nil so the payload is `[]` instead of `null`
	}

	// Remove the object metadata to reduce payload size
	for i := range namespaceEvents {
		namespaceEvents[i].ObjectMeta = v1.ObjectMeta{}
	}

	// Generate an artificial event for the agent pod to include its status in the initial heartbeat.
	// This helps us identify potential OOM kills.
	generatedPodEvent, err := s.GenerateAgentPodEvent(ctx)
	if err != nil {
		s.logger.ReportError(ctx, err, "error generating agent pod event", "managerError")
	}

	if generatedPodEvent != nil {
		namespaceEvents = append(namespaceEvents, *generatedPodEvent)
	}

	// We currently ignore the errors because most agents will lack the necessary permissions to fetch namespace events.
	namespaceEventsPayload, err := json.Marshal(namespaceEvents)
	if err != nil {
		s.logger.ReportError(ctx, err, "error marshalling namespace events payload", "managerError")
	}

	// Send the initial heartbeat to get the monitored resources and agent configuration
	hb, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       s.GetAgentVersion(),
		CollectorVersion:   s.GetSBOMCollectorVersion(),
		FalcoVersion:       s.GetFalcoVersion(),
		IsInitialHeartbeat: true,
		ClusterIdentifier:  clusterIdentifier,
		NamespaceEvents:    string(namespaceEventsPayload),
		HelmChartsVersion:  helmChartsVersion,
		AgentPodName:       s.GetAgentPodName(),
		AgentNamespace:     s.GetAgentNamespace(),
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending initial heartbeat", "managerError")
		return fmt.Errorf("error sending initial heartbeat: %w", err)
	}

	s.SetExcludedNamespaces(hb.Cluster.ExcludedNamespaces)
	s.SetIncludedNamespaces(hb.Cluster.IncludedNamespaces)

	assetsClient, err := batchclient.NewBatchClient(s.logger.GetLogger(), batchclient.ClientOptions{
		Endpoint:              cfg.APIEndpoint + "/api/assets",
		MaxBatch:              1000,
		FlushEvery:            time.Minute * 1,
		MaxConcurrentRequests: 10,
		CompressionEnabled:    true,
		Token:                 cfg.APIToken,
		HeartbeatService:      s.heartbeatService,
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error creating assets batch client", "managerError")
		return fmt.Errorf("error creating assets batch client: %w", err)
	}
	s.assetsOutputClient = assetsClient

	monitoredResourcesGVKs := make([]string, 0, len(hb.MonitoredResources))
	for _, gvk := range hb.MonitoredResources {
		monitoredResourcesGVKs = append(monitoredResourcesGVKs, gvk.String())
	}
	s.SetMonitoredResources(monitoredResourcesGVKs)

	sbomController := httpcontrollers.NewSBOMController(s.logger.GetLogger(), sbom.NewService(s.logger, s.AgentState, s.scannedImagesCache))

	// Initialize the HTTP server that communicates with other components (e.g. the SBOM collector)
	s.SetSBOMCollectorEnabled(hb.Cluster.SBOMCollectorEnabled)
	go func() {
		if err := internalhttp.ListenAndServe(ctx, s.logger.GetLogger(), environmentConfig.APIPort, sbomController); err != nil {
			s.logger.ReportError(ctx, err, "error starting sbom controller", "managerError")
		}
	}()

	if environmentConfig.SBOMCollectorEnabled == nil {
		environmentConfig.SBOMCollectorEnabled = &hb.Cluster.SBOMCollectorEnabled
	}
	s.SetChartsSBOMCollectorEnabled(*environmentConfig.SBOMCollectorEnabled)

	// Configure the SBOM collector deployment/daemonset based on the current enabled state.
	if err := s.ConfigureSBOMCollector(ctx, s.IsSBOMCollectorEnabled(), s.IsChartsSBOMCollectorEnabled()); err != nil {
		s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
	}

	// If the SBOM collector is enabled, load the already scanned images from the API server into the cache and configure the collector.
	if s.IsSBOMCollectorEnabled() && s.IsChartsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err := LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		}
		s.SetSBOMCollectorVersion(sbomCollectorVersion)

		// Load the scanned images cache
		collectorScannedImages, err := s.ListCollectorScannedImages(ctx)
		if err != nil {
			s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
		}

		if len(collectorScannedImages) > 0 {
			s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
		}

		// Load the SBOM collector service account
		sa, err := s.GetSBOMCollectorServiceAccount(ctx)
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector service account from context", "managerError")
		}
		s.SetSBOMCollectorServiceAccount(sa)
	}

	// Threat detection initialization
	s.SetChartsThreatDetectionEnabled(environmentConfig.ThreatDetectionEnabled)
	s.SetThreatDetectionEnabled(hb.Cluster.ThreatDetectionEnabled)
	s.SetEnabledThreatRules(hb.EnabledThreatRules)
	if hb.ThreatDetectionExceptions != nil {
		s.SetThreatDetectionExceptions(*hb.ThreatDetectionExceptions)
	}

	// If threat detection is enabled, write embedded rules and apply the enabled-rules and exceptions configs.
	if s.IsChartsThreatDetectionEnabled() && s.IsThreatDetectionEnabled() {
		falcoVersion, err := LoadDaemonSetVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetThreatDetectorDaemonSetName())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading falco version from daemonset", "managerError")
		}
		s.SetFalcoVersion(falcoVersion)

		if err := s.WriteEmbeddedThreatRules(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error writing embedded threat rules to configmap", "managerError")
		}

		if err := s.rebuildFalcoRulesConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error updating enabled threat detection rules", "managerError")
		}

		if err := s.rebuildFalcoExceptionsConfig(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error updating threat detection exceptions", "managerError")
		}

		if err := s.RestartDaemonSet(ctx, s.GetThreatDetectorDaemonSetName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting threat detection daemonset", "managerError")
		}
	}

	watcherOptions := controller.Options{
		CacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
	}

	// Get the available resources from the Kubernetes API server.
	_, serverResources, err := s.kubernetesClientSet.Discovery().ServerGroupsAndResources()
	if err != nil {
		if !discovery.IsGroupDiscoveryFailedError(err) {
			s.logger.ReportError(ctx, err, "error getting server resources", "managerError")
		}
	}

	// Build a map of available GVKs in the cluster for quick lookup.
	// This is used to skip setting up watchers for resources that are not available in the cluster.
	serverResourcesGVKs := make(map[string]struct{})
	for _, apiResourceList := range serverResources {
		for _, apiResource := range apiResourceList.APIResources {
			gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
			if err != nil {
				s.logger.ReportError(ctx, err, "error parsing group version", "managerError")
				continue
			}

			gvk := schema.GroupVersionKind{Group: gv.Group, Version: gv.Version, Kind: apiResource.Kind}

			serverResourcesGVKs[gvk.String()] = struct{}{}
		}
	}

	agentClusterRole, err := s.kubernetesClientSet.RbacV1().ClusterRoles().Get(ctx, s.GetAgentName(), v1.GetOptions{})
	if err != nil {
		s.logger.ReportError(ctx, err, "error getting agent cluster role", "managerError")
		return fmt.Errorf("error getting agent cluster role: %w", err)
	}

	restMapper := runtimeManager.GetRESTMapper()

	// Set up the resource watchers based on the monitored resources from the heartbeat
	for _, v := range hb.MonitoredResources {
		createController, err := s.ShouldCreateController(serverResourcesGVKs, v, restMapper, agentClusterRole)
		if err != nil {
			s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
			return fmt.Errorf("error checking if controller should be created: %w", err)
		}

		if !createController {
			continue
		}

		watcherSelector := models.WatcherSelector{
			GroupVersionKind: v,
			NamespaceFilter:  predicates.NewNamespaceFilter(s.logger, hb.Cluster.ExcludedNamespaces, hb.Cluster.IncludedNamespaces),
		}

		if err = (&controllers.Watcher{
			Logger:       s.logger,
			Client:       runtimeManager.GetClient(),
			Scheme:       runtimeManager.GetScheme(),
			Watched:      watcherSelector,
			OutputClient: assetsClient,
			PendingMu:    sync.Mutex{},
			Pending:      make(map[string]time.Time),
			AgentState:   s.AgentState,
		}).SetupWithManager(runtimeManager, watcherOptions); err != nil {
			s.logger.ReportError(ctx, err, "error creating new watcher", "managerError")
			return fmt.Errorf("error creating watcher (%s): %w", v.String(), err)
		}
	}

	// Check if ImageContentSourcePolicy is available in the cluster
	createICSPController, err := s.ShouldCreateController(serverResourcesGVKs, openshift.ImageContentSourcePolicyGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createICSPController {
		s.logger.LogInfo("ImageContentSourcePolicy is available in the cluster")
		s.SetImageMappingEnabled(true)
		// Create an ImageContentSourcePolicy controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageContentSourcePolicyController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageContentSourcePolicy controller", "managerError")
		}
	}

	// Check if ImageDigestMirrorSet is available in the cluster
	createIDMSController, err := s.ShouldCreateController(serverResourcesGVKs, openshift.ImageDigestMirrorSetGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createIDMSController {
		s.logger.LogInfo("ImageDigestMirrorSet is available in the cluster")
		s.SetImageMappingEnabled(true)
		// Create an ImageDigestMirrorSet controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageDigestMirrorSetController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageDigestMirrorSet controller", "managerError")
		}
	}

	// Check if ImageTagMirrorSet is available in the cluster
	createITMSController, err := s.ShouldCreateController(serverResourcesGVKs, openshift.ImageTagMirrorSetGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createITMSController {
		s.logger.LogInfo("ImageTagMirrorSet is available in the cluster")
		s.SetImageMappingEnabled(true)
		// Create an ImageTagMirrorSet controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageTagMirrorSetController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageTagMirrorSet controller", "managerError")
		}
	}

	s.StartHeartbeat()

	s.logger.LogInfo("starting agent", "version", s.GetAgentVersion(), "excluded_namespaces", hb.Cluster.ExcludedNamespaces, "included_namespaces", hb.Cluster.IncludedNamespaces)

	return nil
}

// RestartDeployment fetches the deployment and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) RestartDeployment(ctx context.Context, deploymentName string) error {
	if IsLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting deployment: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating deployment: %w", err)
	}

	return nil
}

// UpdateAgentVersion updates the agent deployment with a new image version and updates the version labels
func (s *Service) UpdateAgentVersion(ctx context.Context, newVersion string) error {
	if IsLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetAgentName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent deployment: %w", err)
	}

	image := deployment.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	deployment.Spec.Template.Spec.Containers[0].Image = newImage
	deployment.Labels["app.kubernetes.io/version"] = newVersion
	deployment.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}

	// We're setting the agent version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetAgentVersion(newVersion)
	return nil
}

// UpdateAPIToken updates the API token in the service, output clients and in the agent Kubernetes secret
func (s *Service) UpdateAPIToken(ctx context.Context, newToken string) error {
	if err := s.updateAgentSecret(ctx, newToken); err != nil {
		return fmt.Errorf("error updating agent secret: %w", err)
	}
	s.SetAPIToken(newToken)

	// Set the token for the output clients
	s.assetsOutputClient.SetAPIToken(s.GetAPIToken())
	s.logger.SetAPIToken(s.GetAPIToken())

	if s.falcoProxy != nil {
		s.falcoProxy.SetAPIToken(s.GetAPIToken())
	}

	// Set the heartbeat service token
	s.heartbeatService.SetAPIToken(s.GetAPIToken())

	return nil
}

// updateAgentSecret identifies the agent secret in Kubernetes using the agent name and namespace and updates the API token
func (s *Service) updateAgentSecret(ctx context.Context, newToken string) error {
	secret, err := s.kubernetesClientSet.CoreV1().Secrets(s.GetAgentNamespace()).Get(ctx, s.GetConfigSecretName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent secret to update API token: %w", err)
	}

	var cfg models.Config
	if err := yaml.Unmarshal(secret.Data["config.yaml"], &cfg); err != nil {
		return fmt.Errorf("error unmarshalling agent config from secret: %w", err)
	}
	cfg.APIToken = newToken

	newCfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("error marshalling updated agent config: %w", err)
	}
	secret.Data["config.yaml"] = newCfgData
	secret.Annotations["helm.sh/resource-policy"] = "keep"

	if _, err := s.kubernetesClientSet.CoreV1().Secrets(s.GetAgentNamespace()).Update(ctx, secret, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating agent secret with new API token: %w", err)
	}

	return nil
}

func (s *Service) ConfigureSBOMCollector(ctx context.Context, enabled bool, enabledInCharts bool) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.configureSBOMCollectorDaemonSet(ctx, enabled, enabledInCharts)
	}

	return s.configureSBOMCollectorDeployment(ctx, enabled, enabledInCharts)
}

func (s *Service) configureSBOMCollectorDaemonSet(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if enabled {
		if len(ds.Spec.Template.Spec.NodeSelector) > 0 {
			delete(ds.Spec.Template.Spec.NodeSelector, "aikidoSecurity.disable-sbom-collector")
		}
	} else {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{
			"aikidoSecurity.disable-sbom-collector": "true",
		}
	}

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, ds, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector daemonset: %w", err)
	}
	return nil
}

func (s *Service) configureSBOMCollectorDeployment(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector deployment: %w", err)
	}

	if enabled {
		replicas := int32(1)
		dep.Spec.Replicas = &replicas
	} else {
		replicas := int32(0)
		dep.Spec.Replicas = &replicas
	}

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, dep, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector deployment: %w", err)
	}
	return nil
}

// GetClusterIdentifier extracts the unique identifier for the Kubernetes cluster
func (s *Service) GetClusterIdentifier(ctx context.Context) (string, error) {
	var errs error
	// Check if the cluster is GKE
	identifier, err := s.GetGKEClusterIdentifier(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Check if the cluster is AKS
	identifier, err = s.GetAKSClusterIdentifier(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Try to get the identifier from the kube-proxy configmap
	identifier, err = s.GetClusterIdentifierFromProxy(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Try to get the `kube-system` namespace UID
	identifier, err = s.GetKubeSystemNamespaceUID(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// If all methods fail, return a random UUID to ensure the cluster can still be uniquely identified.
	return uuid.New().String(), multierr.Append(errs, fmt.Errorf("could not get unique cluster identifier"))
}

// GetGKEClusterIdentifier checks if the Kubernetes cluster is GKE and returns the cluster uid if true.
func (s *Service) GetGKEClusterIdentifier(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-uid", nil)
	if err != nil {
		return "", fmt.Errorf("error creating GKE metadata request: %w", err)
	}

	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), noHostErrorMessage) {
			// Not a GKE cluster
			return "", nil
		}

		return "", fmt.Errorf("error getting cluster uid: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.ReportError(ctx, err, "error closing GKE metadata response body", "managerError")
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		// Not a GKE cluster
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from GKE metadata server: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading GKE metadata response body: %w", err)
	}

	clusterUID := string(body)
	return clusterUID, nil
}

// GetAKSClusterIdentifier checks if the Kubernetes cluster is AKS and returns the DNS name if true.
func (s *Service) GetAKSClusterIdentifier(ctx context.Context) (string, error) {
	// Get the kube-proxy pods in the kube-system namespace
	pods, err := s.kubernetesClientSet.CoreV1().Pods("kube-system").List(ctx, v1.ListOptions{
		LabelSelector: "component=kube-proxy,kubernetes.azure.com/managedby=aks",
	})
	if err != nil {
		return "", fmt.Errorf("error getting kube-proxy pods: %w", err)
	}

	// Iterate through all kube-proxy pods
	for _, pod := range pods.Items {
		// Check each environment variable in each container
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.Name != "KUBERNETES_SERVICE_HOST" {
					continue
				}

				// Check if the AKS DNS name is present
				if len(env.Value) == 0 {
					continue
				}

				return env.Value, nil
			}
		}
	}

	return "", nil
}

// GetClusterIdentifierFromProxy extracts the unique identifier for the Kubernetes cluster from the kube-proxy ConfigMap
func (s *Service) GetClusterIdentifierFromProxy(ctx context.Context) (string, error) {
	configMap, err := s.kubernetesClientSet.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-proxy", v1.GetOptions{})
	if err != nil {
		// kube-proxy is not installed in this cluster
		if k8sErrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("error getting kube-proxy configmap: %w", err)
	}

	// Extract the kubeconfig content if exists
	for _, v := range configMap.Data {
		// Try to load the kubeconfig content
		config, err := clientcmd.Load([]byte(v))
		if err != nil {
			continue
		}

		// Get the current context
		contextName := config.CurrentContext
		ctx, ok := config.Contexts[contextName]
		if !ok {
			continue
		}

		// Get the cluster information
		cluster, ok := config.Clusters[ctx.Cluster]
		if ok {
			return cluster.Server, nil
		}
	}

	return "", nil
}

func (s *Service) GetKubeSystemNamespaceUID(ctx context.Context) (string, error) {
	// Get the `kube-system` namespace
	ns, err := s.kubernetesClientSet.CoreV1().Namespaces().Get(ctx, "kube-system", v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting `kube-system` namespace: %w", err)
	}

	return string(ns.UID), nil
}

// RegisterFalcoProxy injects the Falco event proxy into the manager (when threat detection is enabled).
func (s *Service) RegisterFalcoProxy(proxy *falco.Proxy) {
	s.falcoProxy = proxy
}

func (s *Service) GetDeploymentAndChartsVersions(ctx context.Context, ns, deploymentName string) (string, string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, defaultAgentVersion, nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", "", fmt.Errorf("agent version label not found on deployment")
	}

	chartsVersion, ok := deployment.Labels["helm.sh/chart"]
	if !ok {
		return "", "", fmt.Errorf("helm chart version label not found on deployment")
	}

	return agentVersion, chartsVersion, nil
}

func LoadSBOMCollectorVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, ownerName string, isDaemonSet bool) (string, error) {
	if isDaemonSet {
		return LoadDaemonSetVersion(ctx, clientSet, ns, ownerName)
	}
	return LoadDeploymentVersion(ctx, clientSet, ns, ownerName)
}

// LoadDeploymentVersion gets the deployment details from the API server and extracts the version from the labels
func LoadDeploymentVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, deploymentName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}

// LoadDaemonSetVersion gets the daemonSet details from the API server and extracts the version from the labels
func LoadDaemonSetVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, dsName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().DaemonSets(ns).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting daemonSet: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}

func (s *Service) RestartSBOMCollector(ctx context.Context) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.RestartDaemonSet(ctx, s.GetSBOMCollectorName())
	}

	return s.RestartDeployment(ctx, s.GetSBOMCollectorName())
}

// RestartDaemonSet fetches the daemonSet and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) RestartDaemonSet(ctx context.Context, dsName string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting daemonSet: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating daemonSet: %w", err)
	}

	return nil
}

func (s *Service) UpdateSBOMCollectorVersion(ctx context.Context, newVersion string) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.UpdateSBOMCollectorDaemonSetVersion(ctx, newVersion)
	}

	return s.UpdateSBOMCollectorDeploymentVersion(ctx, newVersion)
}

// UpdateSBOMCollectorDeploymentVersion updates the sbom collector deployment with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDeploymentVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
	}

	image := deployment.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	deployment.Spec.Template.Spec.Containers[0].Image = newImage
	deployment.Labels["app.kubernetes.io/version"] = newVersion
	deployment.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
	return nil
}

// UpdateSBOMCollectorDaemonSetVersion updates the sbom collector daemonSet with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDaemonSetVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
	}

	image := daemonSet.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	daemonSet.Spec.Template.Spec.Containers[0].Image = newImage
	daemonSet.Labels["app.kubernetes.io/version"] = newVersion
	daemonSet.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, daemonSet, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
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
		imageParts := strings.Split(container.Image, ":")
		if len(imageParts) == 2 {
			daemonSet.Spec.Template.Spec.Containers[i].Image = fmt.Sprintf("%s:%s", imageParts[0], newVersion)
		}
	}

	for i, container := range daemonSet.Spec.Template.Spec.InitContainers {
		imageParts := strings.Split(container.Image, ":")
		if len(imageParts) == 2 {
			daemonSet.Spec.Template.Spec.InitContainers[i].Image = fmt.Sprintf("%s:%s", imageParts[0], newVersion)
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

func (s *Service) ListCollectorScannedImages(ctx context.Context) ([]models.ScannedImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/sbom/list-scanned-images", s.GetAPIEndpoint()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.GetAPIToken())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to get collector scanned images: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			s.logger.ReportError(ctx, err, "error closing list collector scanned images body", "managerError")
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error listing collector scanned images, status code: %d", res.StatusCode)
	}

	var response []models.ScannedImage
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Service) GetAgentMetrics(ctx context.Context) (models.ComponentMetrics, error) {
	podMetrics, err := s.metricClient.MetricsV1beta1().PodMetricses(s.GetAgentNamespace()).Get(ctx, s.GetAgentPodName(), v1.GetOptions{})
	if err != nil {
		// The metrics for the agent might not have been generated yet (it takes ~60s after the pod starts) or the
		// metrics server might be temporarily unavailable or not installed.
		if k8sErrors.IsNotFound(err) || k8sErrors.IsServiceUnavailable(err) {
			return models.ComponentMetrics{}, nil
		}
		return models.ComponentMetrics{}, fmt.Errorf("error getting agent pod metrics: %w", err)
	}

	if len(podMetrics.Containers) == 0 {
		return models.ComponentMetrics{}, nil
	}

	cpuUsage := podMetrics.Containers[0].Usage.Cpu().MilliValue()

	memUsage := podMetrics.Containers[0].Usage.Memory()

	return models.ComponentMetrics{CPUUsage: fmt.Sprintf("%dm", cpuUsage), MemoryUsage: fmt.Sprintf("%.0fMi", float64(memUsage.Value())/(1024*1024))}, nil
}

func (s *Service) ListResourceEvents(ctx context.Context, kind, name string) ([]corev1.Event, error) {
	fieldSelector := fmt.Sprintf("involvedObject.kind=%s,involvedObject.name=%s", kind, name)
	return s.ListEventsByFieldSelector(ctx, fieldSelector)
}

func (s *Service) ListEventsByFieldSelector(ctx context.Context, fieldSelector string) ([]corev1.Event, error) {
	opts := v1.ListOptions{}
	if fieldSelector != "" {
		opts.FieldSelector = fieldSelector
	}
	eventsList, err := s.kubernetesClientSet.CoreV1().Events(s.GetAgentNamespace()).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("error listing resource events: %w", err)
	}

	events := make([]corev1.Event, 0, len(eventsList.Items))
	// Filter out irrelevant events by reason.
	for _, event := range eventsList.Items {
		if slices.Contains(ignoredEventsReasons, event.Reason) {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

func (s *Service) GenerateAgentPodEvent(ctx context.Context) (*corev1.Event, error) {
	agentPodDetails, err := s.GetPodByName(ctx, s.GetAgentPodName())
	if err != nil {
		return nil, fmt.Errorf("error getting agent pod: %w", err)
	}

	if len(agentPodDetails.Status.ContainerStatuses) == 0 {
		return nil, nil
	}

	event := &corev1.Event{
		TypeMeta: agentPodDetails.TypeMeta,
		InvolvedObject: corev1.ObjectReference{
			Kind:            "Pod",
			Namespace:       agentPodDetails.Namespace,
			Name:            agentPodDetails.Name,
			UID:             agentPodDetails.UID,
			APIVersion:      "v1",
			ResourceVersion: agentPodDetails.ResourceVersion,
		},
		Reason:  "AgentInformation",
		Message: agentPodDetails.Status.ContainerStatuses[0].LastTerminationState.String(),
		Count:   1,
		Type:    "AgentStatusInformation",
	}

	return event, nil
}

func (s *Service) GetPodByName(ctx context.Context, name string) (*corev1.Pod, error) {
	pod, err := s.kubernetesClientSet.CoreV1().Pods(s.GetAgentNamespace()).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting pod by name: %w", err)
	}

	return pod, nil
}

func (s *Service) GetSBOMCollectorServiceAccount(ctx context.Context) (*corev1.ServiceAccount, error) {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.getDaemonsetServiceAccount(ctx, s.GetSBOMCollectorName())
	}

	return s.getDeploymentServiceAccount(ctx, s.GetSBOMCollectorName())
}

func (s *Service) GetServiceAccountByName(ctx context.Context, name string) (*corev1.ServiceAccount, error) {
	sa, err := s.kubernetesClientSet.CoreV1().ServiceAccounts(s.GetAgentNamespace()).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting service account by name: %w", err)
	}

	return sa, nil
}

func (s *Service) getDaemonsetServiceAccount(ctx context.Context, dsName string) (*corev1.ServiceAccount, error) {
	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if ds.Spec.Template.Spec.ServiceAccountName == "" {
		return nil, nil
	}

	return s.GetServiceAccountByName(ctx, ds.Spec.Template.Spec.ServiceAccountName)
}

func (s *Service) getDeploymentServiceAccount(ctx context.Context, depName string) (*corev1.ServiceAccount, error) {
	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, depName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting SBOM collector deployment: %w", err)
	}

	if dep.Spec.Template.Spec.ServiceAccountName == "" {
		return nil, nil
	}

	return s.GetServiceAccountByName(ctx, dep.Spec.Template.Spec.ServiceAccountName)
}

func (s *Service) ShouldCreateController(serverResourcesGVKs map[string]struct{}, gvk schema.GroupVersionKind, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole) (bool, error) {
	// Skip the GVK if it's not available in the cluster
	if _, found := serverResourcesGVKs[gvk.String()]; len(serverResourcesGVKs) > 0 && !found {
		s.logger.LogWarning(fmt.Errorf("GVK %s not found in cluster", gvk.String()), "skipping watcher setup")
		return false, nil
	}

	// Get the REST mapping for the GVK
	mapping, err := restMapper.RESTMapping(
		gvk.GroupKind(),
		gvk.Version,
	)
	if err != nil {
		return false, fmt.Errorf("error getting REST mapping for GVK (`%s`): %w", gvk.String(), err)
	}

	// Skip the GVK if the agent does not have the required permissions to watch it
	if !clusterRoleAllowsWatch(agentClusterRole, gvk.Group, mapping.Resource.Resource) {
		s.logger.LogWarning(fmt.Errorf("agent does not have permissions to watch resource %s", mapping.Resource.Resource), "skipping watcher setup")
		return false, nil
	}

	return true, nil
}

func clusterRoleAllowsWatch(role *rbacv1.ClusterRole, apiGroup, resource string) bool {
	if role == nil {
		return false
	}

	neededVerbs := map[string]bool{
		"get":   false,
		"list":  false,
		"watch": false,
	}

	for _, rule := range role.Rules {
		if !listMatchesValues(rule.APIGroups, apiGroup) {
			continue
		}

		if !listMatchesValues(rule.Resources, resource) {
			continue
		}

		isWildcardVerb := false
		for _, verb := range rule.Verbs {
			if verb == "*" {
				isWildcardVerb = true
				break
			}

			if _, ok := neededVerbs[verb]; ok {
				neededVerbs[verb] = true
			}
		}

		if isWildcardVerb {
			return true
		}

		verbsAllowed := true
		for _, hasVerb := range neededVerbs {
			if hasVerb {
				continue
			}

			verbsAllowed = false
			break
		}

		if verbsAllowed {
			return true
		}
	}

	return false
}

func BuildLocalConfig() (*rest.Config, error) {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func IsLocalEnvironment() bool {
	val, ok := os.LookupEnv("ENVIRONMENT")
	if ok && val == "local" {
		return true
	}

	return false
}

func listMatchesValues(list []string, val string) bool {
	for _, v := range list {
		if v == "*" || v == val {
			return true
		}
	}
	return false
}
