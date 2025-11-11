package models

import (
	"fmt"

	"strconv"
)

type Config struct {
	APIToken        string          `yaml:"apiToken"`
	APIEndpoint     string          `yaml:"apiEndpoint"`
	ThreatDetection ThreatDetection `yaml:"threatDetection"`
}

type ThreatDetection struct {
	Enabled bool   `yaml:"enabled"`
	Port    uint16 `yaml:"port"`
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

// ListenOnPort returns a port agent should listen to in order to receive threat detections from falco agents
func (td ThreatDetection) ListenOnPort() string {
	if td.Port == 0 {
		return "8241" // Our default port for TDR, feel free to change
	}
	return strconv.FormatUint(uint64(td.Port), 10)
}
