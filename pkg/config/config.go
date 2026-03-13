package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"aikidoSec.kubernetesAgent/pkg/models"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
)

const defaultNamespace = "aikido"

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

func ParseEnvironmentConfigs() (models.EnvironmentConfig, error) {
	var errs error
	namespace, exists := os.LookupEnv("AGENT_NAMESPACE")
	if !exists {
		namespace = defaultNamespace
	}

	podName, exists := os.LookupEnv("POD_NAME")
	if !exists {
		errs = multierr.Append(errs, fmt.Errorf("environment variable POD_NAME not set"))
	}

	// Extract the agent name from the Pod name by removing the last two components (replicaset name and random suffix)
	agentNameComponents := strings.Split(podName, "-")
	if len(agentNameComponents) < 3 {
		errs = multierr.Append(errs, fmt.Errorf("invalid POD_NAME format: %s", podName))
	}
	agentName := strings.Join(agentNameComponents[:len(agentNameComponents)-2], "-")

	apiPortStr, exists := os.LookupEnv("API_PORT")
	if !exists {
		apiPortStr = "8091"
	}

	apiPort, err := strconv.Atoi(apiPortStr)
	if err != nil {
		errs = multierr.Append(errs, fmt.Errorf("invalid API_PORT value: %s", apiPortStr))
	}

	metricsPortStr, exists := os.LookupEnv("METRICS_PORT")
	if !exists {
		metricsPortStr = "8080"
	}

	metricsPort, err := strconv.Atoi(metricsPortStr)
	if err != nil {
		errs = multierr.Append(errs, fmt.Errorf("invalid METRICS_PORT value: %s", metricsPortStr))
	}

	controllerCacheSyncTimeoutStr, exists := os.LookupEnv("CONTROLLER_CACHE_SYNC_TIMEOUT")
	if !exists {
		controllerCacheSyncTimeoutStr = "30m"
	}
	controllerCacheSyncTimeout, err := time.ParseDuration(controllerCacheSyncTimeoutStr)
	if err != nil {
		controllerCacheSyncTimeout = 30 * time.Minute
	}

	runSBOMCollectorAsDaemonSetStr, exists := os.LookupEnv("RUN_COLLECTOR_AS_DAEMONSET")
	if !exists {
		runSBOMCollectorAsDaemonSetStr = "true"
	}
	runSBOMCollectorAsDaemonSet, err := strconv.ParseBool(runSBOMCollectorAsDaemonSetStr)
	if err != nil {
		runSBOMCollectorAsDaemonSet = true
	}

	configSecretName, exists := os.LookupEnv("CONFIG_SECRET_NAME")
	if !exists {
		configSecretName = agentName
	}

	var sbomCollectorEnabled *bool
	sbomCollectorEnabledStr, exists := os.LookupEnv("SBOM_COLLECTOR_ENABLED")
	if exists {
		enabled, err := strconv.ParseBool(sbomCollectorEnabledStr)
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("invalid SBOM_COLLECTOR_ENABLED value: %s", sbomCollectorEnabledStr))
		} else {
			sbomCollectorEnabled = &enabled
		}
	}

	autoUpdateEnabled := true
	autoUpdateStr, exists := os.LookupEnv("AUTO_UPDATE_ENABLED")
	if exists {
		enabled, err := strconv.ParseBool(autoUpdateStr)
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("invalid AUTO_UPDATE_ENABLED value: %w", err))
		} else {
			autoUpdateEnabled = enabled
		}
	}

	threatDetectionEnabledStr, exists := os.LookupEnv("THREAT_DETECTION_ENABLED")
	if !exists {
		threatDetectionEnabledStr = "false"
	}
	threatDetectionEnabled, err := strconv.ParseBool(threatDetectionEnabledStr)
	if err != nil {
		threatDetectionEnabled = false
	}

	falcoProxyPortStr, exists := os.LookupEnv("FALCO_PROXY_PORT")
	if !exists {
		falcoProxyPortStr = "8241"
	}

	falcoProxyPort, err := strconv.Atoi(falcoProxyPortStr)
	if err != nil {
		errs = multierr.Append(errs, fmt.Errorf("invalid FALCO_PROXY_PORT value: %s", falcoProxyPortStr))
	}

	return models.EnvironmentConfig{
		Namespace:                   namespace,
		AgentName:                   agentName,
		APIPort:                     apiPort,
		ControllerCacheSyncTimeout:  controllerCacheSyncTimeout,
		RunSBOMCollectorAsDaemonSet: runSBOMCollectorAsDaemonSet,
		ConfigSecretName:            configSecretName,
		AgentPodName:                podName,
		MetricsPort:                 metricsPort,
		SBOMCollectorEnabled:        sbomCollectorEnabled,
		AutoUpdateEnabled:           autoUpdateEnabled,
		ThreatDetectionEnabled:      threatDetectionEnabled,
		FalcoProxyPort:              falcoProxyPort,
	}, errs
}
