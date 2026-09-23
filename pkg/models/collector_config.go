package models

import "time"

type CollectorConfig struct {
	ExcludedNamespaces         []string      `json:"excludedNamespaces"`
	IncludedNamespaces         []string      `json:"includedNamespaces"`
	APIHost                    string        `json:"apiHost"`
	ControllerCacheSyncTimeout time.Duration `json:"controllerCacheSyncTimeout"`
	Namespace                  string        `json:"namespace"`
	ServiceAccountName         string        `json:"serviceAccountName"`
	ServiceAccountPullSecrets  []string      `json:"serviceAccountPullSecrets"`
}
