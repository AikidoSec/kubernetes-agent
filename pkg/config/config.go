package config

import (
	"fmt"
	"os"

	"aikidoSec.kubernetesAgent/pkg/models"
	"gopkg.in/yaml.v3"
)

func ParseConfigFromFile(path string) (models.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return models.Config{}, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var config models.Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return models.Config{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	if err := config.Validate(); err != nil {
		return models.Config{}, fmt.Errorf("invalid config file %s: %w", path, err)
	}

	// Remove the trailing slash if present
	if config.APIEndpoint[len(config.APIEndpoint)-1] == '/' {
		config.APIEndpoint = config.APIEndpoint[:len(config.APIEndpoint)-1]
	}

	return config, nil
}
