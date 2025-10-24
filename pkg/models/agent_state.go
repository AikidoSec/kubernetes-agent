package models

import "time"

type AgentState struct {
	agentVersion               string
	agentNamespace             string
	agentName                  string
	apiToken                   string
	apiEndpoint                string
	excludedNamespaces         []string
	monitoredResources         []string
	controllerCacheSyncTimeout time.Duration
}

func NewEmptyAgentState() *AgentState {
	return &AgentState{
		excludedNamespaces: make([]string, 0),
		monitoredResources: make([]string, 0),
	}
}

func (a *AgentState) SetInitialValues(agentVersion, agentNamespace, agentName, apiToken, apiEndpoint string, controllerCacheSyncTimeout time.Duration) *AgentState {
	a.agentVersion = agentVersion
	a.agentNamespace = agentNamespace
	a.agentName = agentName
	a.apiToken = apiToken
	a.apiEndpoint = apiEndpoint
	a.controllerCacheSyncTimeout = controllerCacheSyncTimeout
	return a
}

func (a *AgentState) GetAgentVersion() string {
	return a.agentVersion
}

func (a *AgentState) GetAgentNamespace() string {
	return a.agentNamespace
}

func (a *AgentState) GetAgentName() string {
	return a.agentName
}

func (a *AgentState) GetAPIToken() string {
	return a.apiToken
}

func (a *AgentState) GetExcludedNamespaces() []string {
	return a.excludedNamespaces
}

func (a *AgentState) GetMonitoredResources() []string {
	return a.monitoredResources
}

func (a *AgentState) GetAPIEndpoint() string {
	return a.apiEndpoint
}

func (a *AgentState) GetControllerCacheSyncTimeout() time.Duration {
	return a.controllerCacheSyncTimeout
}

func (a *AgentState) SetAgentVersion(version string) {
	a.agentVersion = version
}

func (a *AgentState) SetAgentNamespace(namespace string) {
	a.agentNamespace = namespace
}

func (a *AgentState) SetAgentName(name string) {
	a.agentName = name
}

func (a *AgentState) SetAPIToken(token string) {
	a.apiToken = token
}

func (a *AgentState) SetExcludedNamespaces(namespaces []string) {
	a.excludedNamespaces = namespaces
}

func (a *AgentState) SetMonitoredResources(resources []string) {
	a.monitoredResources = resources
}

func (a *AgentState) SetAPIEndpoint(endpoint string) {
	a.apiEndpoint = endpoint
}

func (a *AgentState) SetControllerCacheSyncTimeout(timeout time.Duration) {
	a.controllerCacheSyncTimeout = timeout
}
