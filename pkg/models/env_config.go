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
}
