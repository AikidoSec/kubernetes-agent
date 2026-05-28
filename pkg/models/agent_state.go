package models

import (
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type AgentState struct {
	agentVersion               string
	agentNamespace             string
	agentName                  string
	apiToken                   string
	apiEndpoint                string
	excludedNamespaces         []string
	includedNamespaces         []string
	monitoredResources         []string
	controllerCacheSyncTimeout time.Duration
	configSecretName           string
	agentPodName               string

	sbomCollectorEnabled        bool
	runSBOMCollectorAsDaemonSet bool
	sbomCollectorVersion        string
	sbomCollectorName           string
	chartsSBOMCollectorEnabled  bool
	autoUpdateEnabled           bool
	isImageMappingEnabled       bool
	imageMirrorMappings         map[string]string
	sbomCollectorServiceAccount *corev1.ServiceAccount

	threatDetectionEnabled         bool
	chartsRuntimeDetectionEnabled bool
	falcoDaemonSetName            string
	enabledThreatRules             []string
	threatDetectionExceptions      []ThreatDetectionException
	falcoVersion                   string

	mu sync.Mutex
}

func NewEmptyAgentState() *AgentState {
	return &AgentState{
		excludedNamespaces:        make([]string, 0),
		includedNamespaces:        make([]string, 0),
		monitoredResources:        make([]string, 0),
		imageMirrorMappings:       make(map[string]string),
		enabledThreatRules:        make([]string, 0),
		threatDetectionExceptions: make([]ThreatDetectionException, 0),
		mu:                        sync.Mutex{},
	}
}

func (a *AgentState) SetInitialValues(agentPodName, agentNamespace, agentName, apiToken, apiEndpoint, configSecretName string, controllerCacheSyncTimeout time.Duration, isSBOMCollectorRunningAsDaemonSet bool, sbomCollectorName string, autoUpdate bool, falcoDaemonSetName string) *AgentState {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.agentNamespace = agentNamespace
	a.agentName = agentName
	a.apiToken = apiToken
	a.apiEndpoint = apiEndpoint
	a.controllerCacheSyncTimeout = controllerCacheSyncTimeout
	a.runSBOMCollectorAsDaemonSet = isSBOMCollectorRunningAsDaemonSet
	a.configSecretName = configSecretName
	a.agentPodName = agentPodName
	a.sbomCollectorName = sbomCollectorName
	a.autoUpdateEnabled = autoUpdate
	a.falcoDaemonSetName = falcoDaemonSetName
	return a
}

func (a *AgentState) GetAgentVersion() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentVersion
}

func (a *AgentState) GetAgentNamespace() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentNamespace
}

func (a *AgentState) GetAgentName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentName
}

func (a *AgentState) GetAPIToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.apiToken
}

func (a *AgentState) GetExcludedNamespaces() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.excludedNamespaces
}

func (a *AgentState) GetIncludedNamespaces() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.includedNamespaces
}

func (a *AgentState) GetMonitoredResources() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.monitoredResources
}

func (a *AgentState) GetAPIEndpoint() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.apiEndpoint
}

func (a *AgentState) GetControllerCacheSyncTimeout() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.controllerCacheSyncTimeout
}

func (a *AgentState) IsSBOMCollectorEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sbomCollectorEnabled
}

func (a *AgentState) GetRunSBOMCollectorAsDaemonSet() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runSBOMCollectorAsDaemonSet
}

func (a *AgentState) GetAutoUpdateEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.autoUpdateEnabled
}

func (a *AgentState) GetSBOMCollectorVersion() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sbomCollectorVersion
}

func (a *AgentState) GetConfigSecretName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.configSecretName
}

func (a *AgentState) GetAgentPodName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentPodName
}

func (a *AgentState) GetSBOMCollectorName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sbomCollectorName
}

func (a *AgentState) GetSBOMCollectorServiceAccount() *corev1.ServiceAccount {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sbomCollectorServiceAccount
}

func (a *AgentState) SetChartsSBOMCollectorEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.chartsSBOMCollectorEnabled = enabled
}

func (a *AgentState) IsChartsRuntimeDetectionEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chartsRuntimeDetectionEnabled
}

func (a *AgentState) SetChartsRuntimeDetectionEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.chartsRuntimeDetectionEnabled = enabled
}

func (a *AgentState) SetThreatDetectionEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.threatDetectionEnabled = enabled
}

func (a *AgentState) GetEnabledThreatRules() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabledThreatRules
}

func (a *AgentState) GetFalcoDaemonSetName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.falcoDaemonSetName
}

func (a *AgentState) GetFalcoRulesConfigMapName() string {
	return "kubernetes-agent-falco-rules"
}

func (a *AgentState) GetFalcoConfigMapName() string {
	return "kubernetes-agent-falco-config"
}

func (a *AgentState) SetAgentVersion(version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentVersion = version
}

func (a *AgentState) SetAgentNamespace(namespace string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentNamespace = namespace
}

func (a *AgentState) SetAgentName(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentName = name
}

func (a *AgentState) SetAPIToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiToken = token
}

func (a *AgentState) SetExcludedNamespaces(namespaces []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.excludedNamespaces = namespaces
}

func (a *AgentState) SetIncludedNamespaces(namespaces []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.includedNamespaces = namespaces
}

func (a *AgentState) SetMonitoredResources(resources []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.monitoredResources = resources
}

func (a *AgentState) SetAPIEndpoint(endpoint string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiEndpoint = endpoint
}

func (a *AgentState) SetControllerCacheSyncTimeout(timeout time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.controllerCacheSyncTimeout = timeout
}

func (a *AgentState) SetSBOMCollectorEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sbomCollectorEnabled = enabled
}

func (a *AgentState) SetRunSBOMCollectorAsDaemonSet(runningAsDaemonSet bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.runSBOMCollectorAsDaemonSet = runningAsDaemonSet
}

func (a *AgentState) SetSBOMCollectorVersion(version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sbomCollectorVersion = version
}

func (a *AgentState) SetConfigSecretName(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configSecretName = name
}

func (a *AgentState) SetAgentPodName(podName string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentPodName = podName
}

func (a *AgentState) SetSBOMCollectorName(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sbomCollectorName = name
}

func (a *AgentState) IsChartsSBOMCollectorEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chartsSBOMCollectorEnabled
}

func (a *AgentState) IsImageMappingEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isImageMappingEnabled
}

func (a *AgentState) SetImageMappingEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.isImageMappingEnabled = enabled
}

func (a *AgentState) GetImageMirrorMapping(image string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.imageMirrorMappings[image]
}

func (a *AgentState) GetImageMirrorMappings() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.imageMirrorMappings
}

func (a *AgentState) SetImageMirrorMappings(mappings map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range mappings {
		a.imageMirrorMappings[k] = v
	}
}

func (a *AgentState) SetImageMirrorMapping(image, mirror string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.imageMirrorMappings[image] = mirror
}

func (a *AgentState) SetSBOMCollectorServiceAccount(sa *corev1.ServiceAccount) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sbomCollectorServiceAccount = sa
}

func (a *AgentState) IsThreatDetectionEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.threatDetectionEnabled
}

func (a *AgentState) SetEnabledThreatRules(rules []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabledThreatRules = rules
}

func (a *AgentState) GetThreatDetectionExceptions() []ThreatDetectionException {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.threatDetectionExceptions
}

func (a *AgentState) SetThreatDetectionExceptions(exceptions []ThreatDetectionException) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.threatDetectionExceptions = exceptions
}

func (a *AgentState) GetFalcoVersion() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.falcoVersion
}

func (a *AgentState) SetFalcoVersion(version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.falcoVersion = version
}
