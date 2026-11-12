package models

import "time"

type CollectorConfig struct {
	ClusterIdentifier          string            `json:"clusterIdentifier"`
	SharedToken                SharedTokenConfig `json:"sharedToken"`
	ExcludedNamespaces         []string          `json:"excludedNamespaces"`
	IncludedNamespaces         []string          `json:"includedNamespaces"`
	APIHost                    string            `json:"apiHost"`
	APIToken                   string            `json:"apiToken"`
	ControllerCacheSyncTimeout time.Duration     `json:"controllerCacheSyncTimeout"`
	Namespace                  string            `json:"namespace"`
	ServiceAccountName         string            `json:"serviceAccountName"`
	ServiceAccountPullSecrets  []string          `json:"serviceAccountPullSecrets"`
}
