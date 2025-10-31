package models

type Metrics struct {
	AgentMetrics ComponentMetrics `json:"agent_metrics"`
}

type ComponentMetrics struct {
	CPUUsage    string `json:"cpu_usage"`
	MemoryUsage string `json:"memory_usage"`
}
