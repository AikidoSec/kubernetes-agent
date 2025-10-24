package models

import (
	"fmt"
	"time"
)

type Config struct {
	APIToken                          string        `yaml:"apiToken"`
	APIEndpoint                       string        `yaml:"apiEndpoint"`
	ControllerCacheSyncTimeout        time.Duration `yaml:"controllerCacheSyncTimeout"`
	IsSBOMCollectorRunningAsDaemonSet bool          `yaml:"isSBOMCollectorRunningAsDaemonSet"`
}

func (c *Config) Validate() error {
	if c.APIToken == "" {
		return fmt.Errorf("apiToken is required")
	}
	if c.APIEndpoint == "" {
		return fmt.Errorf("apiEndpoint is required")
	}
	return nil
}
