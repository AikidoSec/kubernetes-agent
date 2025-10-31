package models

type Metrics struct {
	AgentMetrics ComponentMetrics `json:"agent_metrics"`
}

type ComponentMetrics struct {
	CPUUsage    string `json:"cpu_usage"`    // CPU usage in millicores
	MemoryUsage string `json:"memory_usage"` // Memory usage in Mi
}
