package models

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type SharedTokenConfig struct {
	Enabled           bool   `json:"enabled"`
	ClusterIdentifier string `json:"clusterIdentifier"`
}

type Config struct {
	APIToken                 string            `yaml:"apiToken"`
	APIEndpoint              string            `yaml:"apiEndpoint"`
	RuntimeDetectionEndpoint string            `yaml:"runtimeDetectionEndpoint"`
	SharedToken              SharedTokenConfig `yaml:"-"`
}

func (c *Config) Validate() error {
	if c.APIToken == "" {
		return fmt.Errorf("apiToken is required")
	}

	if c.APIEndpoint == "" {
		return fmt.Errorf("apiEndpoint is required")
	}

	if c.SharedToken.Enabled {
		if strings.TrimSpace(c.SharedToken.ClusterIdentifier) == "" {
			return fmt.Errorf("SHARED_TOKEN_CLUSTER_IDENTIFIER is required when SHARED_TOKEN_ENABLED is true")
		}
		if !utf8.ValidString(c.SharedToken.ClusterIdentifier) || utf8.RuneCountInString(c.SharedToken.ClusterIdentifier) > 150 {
			return fmt.Errorf("SHARED_TOKEN_CLUSTER_IDENTIFIER must contain at most 150 valid UTF-8 characters")
		}
	}
	return nil
}
