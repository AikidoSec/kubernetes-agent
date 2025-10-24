package models

import (
	"sync"
	"time"
)

type AgentState struct {
	agentVersion               string
	agentNamespace             string
	agentName                  string
	apiToken                   string
	apiEndpoint                string
	excludedNamespaces         []string
	monitoredResources         []string
	controllerCacheSyncTimeout time.Duration

	sbomCollectorEnabled              bool
	isSBOMCollectorRunningAsDaemonSet bool

	mu sync.Mutex
}

func NewEmptyAgentState() *AgentState {
	return &AgentState{
		excludedNamespaces: make([]string, 0),
		monitoredResources: make([]string, 0),
		mu:                 sync.Mutex{},
	}
}

func (a *AgentState) SetInitialValues(agentVersion, agentNamespace, agentName, apiToken, apiEndpoint string, controllerCacheSyncTimeout time.Duration, isSBOMCollectorRunningAsDaemonSet bool) *AgentState {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.agentVersion = agentVersion
	a.agentNamespace = agentNamespace
	a.agentName = agentName
	a.apiToken = apiToken
	a.apiEndpoint = apiEndpoint
	a.controllerCacheSyncTimeout = controllerCacheSyncTimeout
	a.isSBOMCollectorRunningAsDaemonSet = isSBOMCollectorRunningAsDaemonSet
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

func (a *AgentState) IsSBOMCollectorRunningAsDaemonSet() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isSBOMCollectorRunningAsDaemonSet
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

func (a *AgentState) SetSBOMCollectorRunningAsDaemonSet(runningAsDaemonSet bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.isSBOMCollectorRunningAsDaemonSet = runningAsDaemonSet
}
