package models

import "time"

type EnvironmentConfig struct {
	Namespace                   string
	PodName                     string
	APIPort                     int
	ControllerCacheSyncTimeout  time.Duration
	RunSBOMCollectorAsDaemonSet bool
	ConfigSecretName            string
}
