package models

import "fmt"

type Config struct {
	APIToken    string `yaml:"apiToken"`
	APIEndpoint string `yaml:"apiEndpoint"`
}

func (c *Config) Validate() error {
	if c.APIToken == "" {
		return fmt.Errorf("api_token is required")
	}
	if c.APIEndpoint == "" {
		return fmt.Errorf("api_endpoint is required")
	}
	return nil
}
