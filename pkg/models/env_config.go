package models

import "time"

type EnvironmentConfig struct {
	Namespace                   string
	AgentName                   string
	APIPort                     int
	MetricsPort                 int
	ControllerCacheSyncTimeout  time.Duration
	RunSBOMCollectorAsDaemonSet bool
	ConfigSecretName            string
	AgentPodName                string
	SBOMCollectorEnabled        *bool
	AutoUpdateEnabled           bool
	RuntimeDetectionEnabled     bool
	RuntimeDetectionPort        int
	FalcoDaemonSetName          string
}

// IsSBOMCollectorDisabledInCharts returns true only when the charts explicitly disable the SBOM collector.
// Older charts don't pass the flag but can still deploy a collector, so a missing value doesn't count as disabled.
func (c EnvironmentConfig) IsSBOMCollectorDisabledInCharts() bool {
	return c.SBOMCollectorEnabled != nil && !*c.SBOMCollectorEnabled
}
