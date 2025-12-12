package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/controllers/openshift"
	internalhttp "aikidoSec.kubernetesAgent/internal/http"
	httpcontrollers "aikidoSec.kubernetesAgent/internal/http/controllers"
	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/sbom"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/imagescache"
	"aikidoSec.kubernetesAgent/pkg/models"

	"github.com/google/uuid"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var noHostErrorMessage = "no such host"

const (
	defaultAgentVersion = "1.0.0"

	openshiftImageContentSourcePolicyGVK = "operator.openshift.io/v1alpha1, Kind=ImageContentSourcePolicy"
)

var ignoredEventsReasons = []string{
	"Pulled",
	"Created",
	"Started",
	"Scheduled",
	"ScalingReplicaSet",
	"SuccessfulCreate",
	"SuccessfulDelete",
}

type Options struct {
	AgentNamespace                    string
	AgentName                         string
	APIToken                          string
	APIEndpoint                       string
	ConfigSecretName                  string
	AgentPodName                      string
	ExcludedNamespaces                []string
	HeartbeatService                  *heartbeat.Service
	AssetsOutputClient                *batchclient.BatchClient
	Logger                            *logger.Service
	ControllerCacheSyncTimeout        time.Duration
	IsSBOMCollectorRunningAsDaemonSet bool
	AutoUpdateEnabled                 bool
}
type Service struct {
	*models.AgentState
	scannedImagesCache *imagescache.ImagesCache
	logger             *logger.Service
	// Channel to stop the heartbeat goroutine.
	heartbeatStopChan   chan struct{}
	kubernetesClientSet *kubernetes.Clientset
	heartbeatService    *heartbeat.Service
	assetsOutputClient  *batchclient.BatchClient
	metricClient        *metricsclient.Clientset
}

func NewService(ctx context.Context, agentState *models.AgentState, o Options) (*Service, error) {
	ctrlConfig, err := ctrlconfig.GetConfig()
	if err != nil {
		o.Logger.ReportError(ctx, err, "error getting kubeconfig", "managerError")
		return nil, fmt.Errorf("error getting kubeconfig: %w", err)
	}

	clientSet, err := kubernetes.NewForConfig(ctrlConfig)
	if err != nil {
		o.Logger.ReportError(ctx, err, "error getting kubernetes clientSet", "managerError")
		return nil, fmt.Errorf("error creating kubernetes client: %w", err)
	}

	// Initialize the agent state with all values from options and context
	agentState.SetInitialValues(
		o.AgentPodName,
		o.AgentNamespace,
		o.AgentName,
		o.APIToken,
		o.APIEndpoint,
		o.ConfigSecretName,
		o.ControllerCacheSyncTimeout,
		o.IsSBOMCollectorRunningAsDaemonSet,
		fmt.Sprintf("%s-sbom-collector", o.AgentName),
		o.AutoUpdateEnabled,
	)

	// Build the cluster configuration based on the environment.
	var cfg *rest.Config
	if IsLocalEnvironment() {
		cfg, err = BuildLocalConfig()
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		o.Logger.LogInfo("unable to use in-cluster config, memory usage reporting will be disabled", "error", err.Error())
	}

	var mClient *metricsclient.Clientset
	if cfg != nil {
		// Create the metrics client
		mClient, err = metricsclient.NewForConfig(cfg)
		if err != nil {
			o.Logger.LogInfo("unable to create metrics client, memory usage reporting will be disabled", "error", err.Error())
			mClient = nil
		}
	}

	return &Service{
		AgentState:          agentState,
		heartbeatStopChan:   make(chan struct{}),
		kubernetesClientSet: clientSet,
		heartbeatService:    o.HeartbeatService,
		logger:              o.Logger,
		assetsOutputClient:  o.AssetsOutputClient,
		metricClient:        mClient,
		scannedImagesCache:  imagescache.NewImagesCache(),
	}, nil
}

func (s *Service) StartHeartbeat() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.LogError(fmt.Errorf("panic recovered: %v", r), "panic recovered in periodic heartbeat")
		}
	}()

	s.heartbeatStopChan = make(chan struct{})
	ticker := time.NewTicker(s.heartbeatService.GetSendInterval())
	go func() {
		for {
			select {
			case <-ticker.C:
				ctx := context.Background()
				if _, err := s.SendHeartbeat(ctx); err != nil {
					s.logger.LogError(err, "error sending heartbeat")
				}
			case <-s.heartbeatStopChan:
				close(s.heartbeatStopChan)
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Service) StopHeartbeat() {
	s.heartbeatStopChan <- struct{}{}
}

func (s *Service) Close(ctx context.Context) {
	s.StopHeartbeat()

	if err := s.assetsOutputClient.Close(ctx); err != nil {
		s.logger.ReportError(ctx, err, "error closing assets output client", "managerError")
	}
}

// SendHeartbeat sends a heartbeat to the management server and processes the response
func (s *Service) SendHeartbeat(ctx context.Context) (models.HeartbeatResponse, error) {
	metrics := models.Metrics{}
	if s.metricClient != nil {
		agentMetrics, _ := s.GetAgentMetrics(ctx)
		// We currently ignore the errors since most agents will lack the necessary permissions to fetch metrics.
		metrics.AgentMetrics = agentMetrics
	}

	metricsPayload, err := json.Marshal(metrics)
	if err != nil {
		s.logger.ReportError(ctx, err, "error marshalling metrics payload", "managerError")
	}

	// Load the agent and charts versions from the deployment labels. We don't use the agent state value here because the version
	// might have been updated in the deployment but the new pod might fail to schedule or start, so we need to know if
	// the old pod is the one that sends the heartbeat.
	// Also, the charts can be updated without triggering a deployment update, so we need to load it every time.
	agentVersion, helmChartsVersion, err := s.GetDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context at heartbeat", "managerError")
	}

	sbomCollectorVersion := s.GetSBOMCollectorVersion()
	if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err = LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		}
	}

	resp, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       agentVersion,
		CollectorVersion:   sbomCollectorVersion,
		IsInitialHeartbeat: false,
		Metrics:            string(metricsPayload),
		HelmChartsVersion:  helmChartsVersion,
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending heartbeat", "managerError")
		return models.HeartbeatResponse{}, err
	}

	// If the token has changed, update it in the service, output clients and in the agent Kubernetes secret
	if s.GetAPIToken() != resp.Token && resp.Token != "" {
		s.logger.LogInfo("API token updated from heartbeat response")
		if err := s.UpdateAPIToken(ctx, resp.Token); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent API token", "managerError")
			return resp, err
		}
	}

	if s.GetAutoUpdateEnabled() {
		// If the agent version has changed, update the deployment with the new image version which will also trigger a restart
		if s.GetAgentVersion() != resp.Cluster.DesiredAgentVersion {
			s.logger.LogInfo("agent version updated from heartbeat response", "current version", s.GetAgentVersion(), "new version", resp.Cluster.DesiredAgentVersion)
			if err := s.UpdateAgentVersion(ctx, resp.Cluster.DesiredAgentVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating agent version", "managerError")
				return resp, err
			}
			s.SetAgentVersion(resp.Cluster.DesiredAgentVersion)
		}
	}

	// If the excluded namespaces have changed, restart the agent to re-create the watchers with the new namespaces filters
	if !slices.Equal(s.GetExcludedNamespaces(), resp.Cluster.ExcludedNamespaces) {
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			s.logger.LogInfo("excluded namespaces changed, restarting sbom collector")
			if err := s.RestartSBOMCollector(ctx); err != nil {
				s.logger.ReportError(ctx, err, "error restarting sbom collector", "managerError")
			}
		}

		s.logger.LogInfo("excluded namespaces changed, restarting agent")
		if err := s.RestartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetExcludedNamespaces(resp.Cluster.ExcludedNamespaces)
	}

	monitoredResourcesGVKs := make([]string, 0, len(resp.MonitoredResources))
	for _, gvk := range resp.MonitoredResources {
		monitoredResourcesGVKs = append(monitoredResourcesGVKs, gvk.String())
	}

	// If the monitored resources have changed, restart the agent to re-create the watchers with the new configuration
	if !slices.Equal(s.GetMonitoredResources(), monitoredResourcesGVKs) {
		s.logger.LogInfo("monitored resources changed, restarting agent")
		if err := s.RestartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetMonitoredResources(monitoredResourcesGVKs)
	}

	// If the SBOM collector enabled state has changed, update the deployment/daemonset accordingly
	if s.IsSBOMCollectorEnabled() != resp.Cluster.SBOMCollectorEnabled {
		s.logger.LogInfo("sbom collector enabled state changed from heartbeat response", "current state", s.IsSBOMCollectorEnabled(), "new state", resp.Cluster.SBOMCollectorEnabled)
		if err := s.ConfigureSBOMCollector(ctx, resp.Cluster.SBOMCollectorEnabled, s.IsChartsSBOMCollectorEnabled()); err != nil {
			s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
			return resp, err
		}
		s.SetSBOMCollectorEnabled(resp.Cluster.SBOMCollectorEnabled)

		// If the SBOM collector was enabled, load the scanned images from the API server into the cache and set the deployed collector version.
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			// Load the SBOM collector version from the deployment labels
			sbomCollectorVersion, err := LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
			if err != nil {
				s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
			}
			s.SetSBOMCollectorVersion(sbomCollectorVersion)
			// Load the scanned images cache
			collectorScannedImages, err := s.ListCollectorScannedImages(ctx)
			if err != nil {
				s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
			}

			if len(collectorScannedImages) > 0 {
				s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
			}
		} else {
			// If the SBOM collector was disabled, clear the collector deployed version.
			s.SetSBOMCollectorVersion("")
		}
	}

	if s.GetAutoUpdateEnabled() {
		// If the SBOM collector version has changed, update it in the service state
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() && s.GetSBOMCollectorVersion() != resp.Cluster.DesiredSBOMCollectorVersion {
			s.logger.LogInfo("sbom collector version updated from heartbeat response", "current version", s.GetSBOMCollectorVersion(), "new version", resp.Cluster.DesiredSBOMCollectorVersion)
			if err := s.UpdateSBOMCollectorVersion(ctx, resp.Cluster.DesiredSBOMCollectorVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating sbom collector version", "managerError")
			}
			s.SetSBOMCollectorVersion(resp.Cluster.DesiredSBOMCollectorVersion)
		}
	}

	return resp, nil
}

func (s *Service) InitializeAgent(ctx context.Context, cfg models.Config, runtimeManager manager.Manager, environmentConfig models.EnvironmentConfig) error {
	// Load the agent and charts versions from the deployment labels
	agentVersion, helmChartsVersion, err := s.GetDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context", "managerError")
		return fmt.Errorf("error loading agent version from context: %w", err)
	}
	s.SetAgentVersion(agentVersion)

	clusterIdentifier, err := s.GetClusterIdentifier(ctx)
	if err != nil {
		s.logger.LogWarning(err, "error getting cluster identifier", "managerError")
	}

	// List all events from the agent namespace.
	namespaceEvents, _ := s.ListEventsByFieldSelector(ctx, "")
	if namespaceEvents == nil {
		namespaceEvents = []corev1.Event{} // empty slice instead of nil so the payload is `[]` instead of `null`
	}

	// Remove the object metadata to reduce payload size
	for i := range namespaceEvents {
		namespaceEvents[i].ObjectMeta = v1.ObjectMeta{}
	}

	// Generate an artificial event for the agent pod to include its status in the initial heartbeat.
	// This helps us identify potential OOM kills.
	generatedPodEvent, err := s.GenerateAgentPodEvent(ctx)
	if err != nil {
		s.logger.ReportError(ctx, err, "error generating agent pod event", "managerError")
	}

	if generatedPodEvent != nil {
		namespaceEvents = append(namespaceEvents, *generatedPodEvent)
	}

	// We currently ignore the errors because most agents will lack the necessary permissions to fetch namespace events.
	namespaceEventsPayload, err := json.Marshal(namespaceEvents)
	if err != nil {
		s.logger.ReportError(ctx, err, "error marshalling namespace events payload", "managerError")
	}

	// Send the initial heartbeat to get the monitored resources and agent configuration
	hb, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       s.GetAgentVersion(),
		CollectorVersion:   s.GetSBOMCollectorVersion(),
		IsInitialHeartbeat: true,
		ClusterIdentifier:  clusterIdentifier,
		NamespaceEvents:    string(namespaceEventsPayload),
		HelmChartsVersion:  helmChartsVersion,
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending initial heartbeat", "managerError")
		return fmt.Errorf("error sending initial heartbeat: %w", err)
	}
	s.SetExcludedNamespaces(hb.Cluster.ExcludedNamespaces)

	assetsClient, err := batchclient.NewBatchClient(s.logger.GetLogger(), batchclient.ClientOptions{
		Endpoint:              cfg.APIEndpoint + "/api/assets",
		MaxBatch:              1000,
		FlushEvery:            time.Minute * 1,
		MaxConcurrentRequests: 10,
		CompressionEnabled:    true,
		Token:                 cfg.APIToken,
		HeartbeatService:      s.heartbeatService,
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error creating assets batch client", "managerError")
		return fmt.Errorf("error creating assets batch client: %w", err)
	}
	s.assetsOutputClient = assetsClient

	// Append the agent namespace to the excluded namespaces to avoid watching its own resources
	excludedNamespaces := append(hb.Cluster.ExcludedNamespaces, s.GetAgentNamespace())

	monitoredResourcesGVKs := make([]string, 0, len(hb.MonitoredResources))
	for _, gvk := range hb.MonitoredResources {
		monitoredResourcesGVKs = append(monitoredResourcesGVKs, gvk.String())
	}
	s.SetMonitoredResources(monitoredResourcesGVKs)

	sbomController := httpcontrollers.NewSBOMController(s.logger.GetLogger(), sbom.NewService(s.logger, s.AgentState, s.scannedImagesCache))

	// Initialize the HTTP server that communicates with other components (e.g. the SBOM collector)
	s.SetSBOMCollectorEnabled(hb.Cluster.SBOMCollectorEnabled)
	go func() {
		if err := internalhttp.ListenAndServe(ctx, s.logger.GetLogger(), environmentConfig.APIPort, sbomController); err != nil {
			s.logger.ReportError(ctx, err, "error starting sbom controller", "managerError")
		}
	}()

	if environmentConfig.SBOMCollectorEnabled == nil {
		environmentConfig.SBOMCollectorEnabled = &hb.Cluster.SBOMCollectorEnabled
	}
	s.SetChartsSBOMCollectorEnabled(*environmentConfig.SBOMCollectorEnabled)

	// Configure the SBOM collector deployment/daemonset based on the current enabled state.
	if err := s.ConfigureSBOMCollector(ctx, s.IsSBOMCollectorEnabled(), s.IsChartsSBOMCollectorEnabled()); err != nil {
		s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
	}

	// If the SBOM collector is enabled, load the already scanned images from the API server into the cache and configure the collector.
	if s.IsSBOMCollectorEnabled() && s.IsChartsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err := LoadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		}
		s.SetSBOMCollectorVersion(sbomCollectorVersion)

		collectorScannedImages, err := s.ListCollectorScannedImages(ctx)
		if err != nil {
			s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
		}

		if len(collectorScannedImages) > 0 {
			s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
		}
	}

	watcherOptions := controller.Options{
		CacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
	}

	// Get the available resources from the Kubernetes API server.
	_, serverResources, err := s.kubernetesClientSet.Discovery().ServerGroupsAndResources()
	if err != nil {
		if !discovery.IsGroupDiscoveryFailedError(err) {
			s.logger.ReportError(ctx, err, "error getting server resources", "managerError")
		}
	}

	// Build a map of available GVKs in the cluster for quick lookup.
	// This is used to skip setting up watchers for resources that are not available in the cluster.
	serverResourcesGVKs := make(map[string]struct{})
	for _, apiResourceList := range serverResources {
		for _, apiResource := range apiResourceList.APIResources {
			gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
			if err != nil {
				s.logger.ReportError(ctx, err, "error parsing group version", "managerError")
				continue
			}

			gvk := schema.GroupVersionKind{Group: gv.Group, Version: gv.Version, Kind: apiResource.Kind}

			serverResourcesGVKs[gvk.String()] = struct{}{}
		}
	}

	// Set up the resource watchers based on the monitored resources from the heartbeat
	for _, v := range hb.MonitoredResources {
		// Skip the GVK if it's not available in the cluster
		if _, found := serverResourcesGVKs[v.String()]; len(serverResourcesGVKs) > 0 && !found {
			s.logger.LogWarning(fmt.Errorf("GVK %s not found in cluster", v.String()), "skipping watcher setup")
			continue
		}

		watcherSelector := models.WatcherSelector{
			GroupVersionKind:   v,
			ExcludedNamespaces: excludedNamespaces,
		}

		if err = (&controllers.Watcher{
			Logger:       s.logger,
			Client:       runtimeManager.GetClient(),
			Scheme:       runtimeManager.GetScheme(),
			Watched:      watcherSelector,
			OutputClient: assetsClient,
			PendingMu:    sync.Mutex{},
			Pending:      make(map[string]time.Time),
			AgentState:   s.AgentState,
		}).SetupWithManager(runtimeManager, watcherOptions); err != nil {
			s.logger.ReportError(ctx, err, "error creating new watcher", "managerError")
			return fmt.Errorf("error creating watcher (%s): %w", v.String(), err)
		}
	}

	if _, exists := serverResourcesGVKs[openshift.ImageContentSourcePolicyGVK.String()]; exists {
		s.SetImageMappingEnabled(true)
		// Create an ImageContentSourcePolicy controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageContentSourcePolicyController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageContentSourcePolicy controller", "managerError")
		}
	}

	s.StartHeartbeat()

	s.logger.LogInfo("starting agent", "version", s.GetAgentVersion(), "excluded_namespaces", excludedNamespaces)

	return nil
}

// RestartDeployment fetches the deployment and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) RestartDeployment(ctx context.Context, deploymentName string) error {
	if IsLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting deployment: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating deployment: %w", err)
	}

	return nil
}

// UpdateAgentVersion updates the agent deployment with a new image version and updates the version labels
func (s *Service) UpdateAgentVersion(ctx context.Context, newVersion string) error {
	if IsLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetAgentName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent deployment: %w", err)
	}

	image := deployment.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	deployment.Spec.Template.Spec.Containers[0].Image = newImage
	deployment.Labels["app.kubernetes.io/version"] = newVersion
	deployment.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}

	// We're setting the agent version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetAgentVersion(newVersion)
	return nil
}

// UpdateAPIToken updates the API token in the service, output clients and in the agent Kubernetes secret
func (s *Service) UpdateAPIToken(ctx context.Context, newToken string) error {
	if err := s.updateAgentSecret(ctx, newToken); err != nil {
		return fmt.Errorf("error updating agent secret: %w", err)
	}
	s.SetAPIToken(newToken)

	// Set the token for the output clients
	s.assetsOutputClient.SetAPIToken(s.GetAPIToken())
	s.logger.SetAPIToken(s.GetAPIToken())

	// Set the heartbeat service token
	s.heartbeatService.SetAPIToken(s.GetAPIToken())

	return nil
}

// updateAgentSecret identifies the agent secret in Kubernetes using the agent name and namespace and updates the API token
func (s *Service) updateAgentSecret(ctx context.Context, newToken string) error {
	secret, err := s.kubernetesClientSet.CoreV1().Secrets(s.GetAgentNamespace()).Get(ctx, s.GetConfigSecretName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent secret to update API token: %w", err)
	}

	var cfg models.Config
	if err := yaml.Unmarshal(secret.Data["config.yaml"], &cfg); err != nil {
		return fmt.Errorf("error unmarshalling agent config from secret: %w", err)
	}
	cfg.APIToken = newToken

	newCfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("error marshalling updated agent config: %w", err)
	}
	secret.Data["config.yaml"] = newCfgData
	secret.Annotations["helm.sh/resource-policy"] = "keep"

	if _, err := s.kubernetesClientSet.CoreV1().Secrets(s.GetAgentNamespace()).Update(ctx, secret, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating agent secret with new API token: %w", err)
	}

	return nil
}

func (s *Service) ConfigureSBOMCollector(ctx context.Context, enabled bool, enabledInCharts bool) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.configureSBOMCollectorDaemonSet(ctx, enabled, enabledInCharts)
	}

	return s.configureSBOMCollectorDeployment(ctx, enabled, enabledInCharts)
}

func (s *Service) configureSBOMCollectorDaemonSet(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if enabled {
		if len(ds.Spec.Template.Spec.NodeSelector) > 0 {
			delete(ds.Spec.Template.Spec.NodeSelector, "aikidoSecurity.disable-sbom-collector")
		}
	} else {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{
			"aikidoSecurity.disable-sbom-collector": "true",
		}
	}

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, ds, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector daemonset: %w", err)
	}
	return nil
}

func (s *Service) configureSBOMCollectorDeployment(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector deployment: %w", err)
	}

	if enabled {
		replicas := int32(1)
		dep.Spec.Replicas = &replicas
	} else {
		replicas := int32(0)
		dep.Spec.Replicas = &replicas
	}

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, dep, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector deployment: %w", err)
	}
	return nil
}

// GetClusterIdentifier extracts the unique identifier for the Kubernetes cluster
func (s *Service) GetClusterIdentifier(ctx context.Context) (string, error) {
	var errs error
	// Check if the cluster is GKE
	identifier, err := s.GetGKEClusterIdentifier(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Check if the cluster is AKS
	identifier, err = s.GetAKSClusterIdentifier(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Try to get the identifier from the kube-proxy configmap
	identifier, err = s.GetClusterIdentifierFromProxy(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// Try to get the `kube-system` namespace UID
	identifier, err = s.GetKubeSystemNamespaceUID(ctx)
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	if identifier != "" {
		return identifier, errs
	}

	// If all methods fail, return a random UUID to ensure the cluster can still be uniquely identified.
	return uuid.New().String(), multierr.Append(errs, fmt.Errorf("could not get unique cluster identifier"))
}

// GetGKEClusterIdentifier checks if the Kubernetes cluster is GKE and returns the cluster uid if true.
func (s *Service) GetGKEClusterIdentifier(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-uid", nil)
	if err != nil {
		return "", fmt.Errorf("error creating GKE metadata request: %w", err)
	}

	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), noHostErrorMessage) {
			// Not a GKE cluster
			return "", nil
		}

		return "", fmt.Errorf("error getting cluster uid: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.ReportError(ctx, err, "error closing GKE metadata response body", "managerError")
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		// Not a GKE cluster
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from GKE metadata server: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading GKE metadata response body: %w", err)
	}

	clusterUID := string(body)
	return clusterUID, nil
}

// GetAKSClusterIdentifier checks if the Kubernetes cluster is AKS and returns the DNS name if true.
func (s *Service) GetAKSClusterIdentifier(ctx context.Context) (string, error) {
	// Get the kube-proxy pods in the kube-system namespace
	pods, err := s.kubernetesClientSet.CoreV1().Pods("kube-system").List(ctx, v1.ListOptions{
		LabelSelector: "component=kube-proxy,kubernetes.azure.com/managedby=aks",
	})
	if err != nil {
		return "", fmt.Errorf("error getting kube-proxy pods: %w", err)
	}

	// Iterate through all kube-proxy pods
	for _, pod := range pods.Items {
		// Check each environment variable in each container
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.Name != "KUBERNETES_SERVICE_HOST" {
					continue
				}

				// Check if the AKS DNS name is present
				if len(env.Value) == 0 {
					continue
				}

				return env.Value, nil
			}
		}
	}

	return "", nil
}

// GetClusterIdentifierFromProxy extracts the unique identifier for the Kubernetes cluster from the kube-proxy ConfigMap
func (s *Service) GetClusterIdentifierFromProxy(ctx context.Context) (string, error) {
	configMap, err := s.kubernetesClientSet.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-proxy", v1.GetOptions{})
	if err != nil {
		// kube-proxy is not installed in this cluster
		if k8sErrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("error getting kube-proxy configmap: %w", err)
	}

	// Extract the kubeconfig content if exists
	for _, v := range configMap.Data {
		// Try to load the kubeconfig content
		config, err := clientcmd.Load([]byte(v))
		if err != nil {
			continue
		}

		// Get the current context
		contextName := config.CurrentContext
		ctx, ok := config.Contexts[contextName]
		if !ok {
			continue
		}

		// Get the cluster information
		cluster, ok := config.Clusters[ctx.Cluster]
		if ok {
			return cluster.Server, nil
		}
	}

	return "", nil
}

func (s *Service) GetKubeSystemNamespaceUID(ctx context.Context) (string, error) {
	// Get the `kube-system` namespace
	ns, err := s.kubernetesClientSet.CoreV1().Namespaces().Get(ctx, "kube-system", v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting `kube-system` namespace: %w", err)
	}

	return string(ns.UID), nil
}

func (s *Service) GetDeploymentAndChartsVersions(ctx context.Context, ns, deploymentName string) (string, string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, defaultAgentVersion, nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", "", fmt.Errorf("agent version label not found on deployment")
	}

	chartsVersion, ok := deployment.Labels["helm.sh/chart"]
	if !ok {
		return "", "", fmt.Errorf("helm chart version label not found on deployment")
	}

	return agentVersion, chartsVersion, nil
}

func LoadSBOMCollectorVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, ownerName string, isDaemonSet bool) (string, error) {
	if isDaemonSet {
		return LoadDaemonSetVersion(ctx, clientSet, ns, ownerName)
	}
	return LoadDeploymentVersion(ctx, clientSet, ns, ownerName)
}

// LoadDeploymentVersion gets the deployment details from the API server and extracts the version from the labels
func LoadDeploymentVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, deploymentName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}

// LoadDaemonSetVersion gets the daemonSet details from the API server and extracts the version from the labels
func LoadDaemonSetVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, dsName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().DaemonSets(ns).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting daemonSet: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}

func (s *Service) RestartSBOMCollector(ctx context.Context) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.RestartDaemonSet(ctx, s.GetSBOMCollectorName())
	}

	return s.RestartDeployment(ctx, s.GetSBOMCollectorName())
}

// RestartDaemonSet fetches the daemonSet and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) RestartDaemonSet(ctx context.Context, dsName string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting daemonSet: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating daemonSet: %w", err)
	}

	return nil
}

func (s *Service) UpdateSBOMCollectorVersion(ctx context.Context, newVersion string) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.UpdateSBOMCollectorDaemonSetVersion(ctx, newVersion)
	}

	return s.UpdateSBOMCollectorDeploymentVersion(ctx, newVersion)
}

// UpdateSBOMCollectorDeploymentVersion updates the sbom collector deployment with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDeploymentVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
	}

	image := deployment.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	deployment.Spec.Template.Spec.Containers[0].Image = newImage
	deployment.Labels["app.kubernetes.io/version"] = newVersion
	deployment.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
	return nil
}

// UpdateSBOMCollectorDaemonSetVersion updates the sbom collector daemonSet with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDaemonSetVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
	}

	image := daemonSet.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	daemonSet.Spec.Template.Spec.Containers[0].Image = newImage
	daemonSet.Labels["app.kubernetes.io/version"] = newVersion
	daemonSet.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, daemonSet, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
	return nil
}

func (s *Service) ListCollectorScannedImages(ctx context.Context) ([]models.ScannedImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/sbom/list-scanned-images", s.GetAPIEndpoint()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.GetAPIToken())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to get collector scanned images: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			s.logger.ReportError(ctx, err, "error closing list collector scanned images body", "managerError")
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error listing collector scanned images, status code: %d", res.StatusCode)
	}

	var response []models.ScannedImage
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Service) GetAgentMetrics(ctx context.Context) (models.ComponentMetrics, error) {
	podMetrics, err := s.metricClient.MetricsV1beta1().PodMetricses(s.GetAgentNamespace()).Get(ctx, s.GetAgentPodName(), v1.GetOptions{})
	if err != nil {
		// The metrics for the agent might not have been generated yet (it takes ~60s after the pod starts) or the
		// metrics server might be temporarily unavailable or not installed.
		if k8sErrors.IsNotFound(err) || k8sErrors.IsServiceUnavailable(err) {
			return models.ComponentMetrics{}, nil
		}
		return models.ComponentMetrics{}, fmt.Errorf("error getting agent pod metrics: %w", err)
	}

	if len(podMetrics.Containers) == 0 {
		return models.ComponentMetrics{}, nil
	}

	cpuUsage := podMetrics.Containers[0].Usage.Cpu().MilliValue()

	memUsage := podMetrics.Containers[0].Usage.Memory()

	return models.ComponentMetrics{CPUUsage: fmt.Sprintf("%dm", cpuUsage), MemoryUsage: fmt.Sprintf("%.0fMi", float64(memUsage.Value())/(1024*1024))}, nil
}

func (s *Service) ListResourceEvents(ctx context.Context, kind, name string) ([]corev1.Event, error) {
	fieldSelector := fmt.Sprintf("involvedObject.kind=%s,involvedObject.name=%s", kind, name)
	return s.ListEventsByFieldSelector(ctx, fieldSelector)
}

func (s *Service) ListEventsByFieldSelector(ctx context.Context, fieldSelector string) ([]corev1.Event, error) {
	opts := v1.ListOptions{}
	if fieldSelector != "" {
		opts.FieldSelector = fieldSelector
	}
	eventsList, err := s.kubernetesClientSet.CoreV1().Events(s.GetAgentNamespace()).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("error listing resource events: %w", err)
	}

	events := make([]corev1.Event, 0, len(eventsList.Items))
	// Filter out irrelevant events by reason.
	for _, event := range eventsList.Items {
		if slices.Contains(ignoredEventsReasons, event.Reason) {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

func (s *Service) GenerateAgentPodEvent(ctx context.Context) (*corev1.Event, error) {
	agentPodDetails, err := s.GetPodByName(ctx, s.GetAgentPodName())
	if err != nil {
		return nil, fmt.Errorf("error getting agent pod: %w", err)
	}

	if len(agentPodDetails.Status.ContainerStatuses) == 0 {
		return nil, nil
	}

	event := &corev1.Event{
		TypeMeta: agentPodDetails.TypeMeta,
		InvolvedObject: corev1.ObjectReference{
			Kind:            "Pod",
			Namespace:       agentPodDetails.Namespace,
			Name:            agentPodDetails.Name,
			UID:             agentPodDetails.UID,
			APIVersion:      "v1",
			ResourceVersion: agentPodDetails.ResourceVersion,
		},
		Reason:  "AgentInformation",
		Message: agentPodDetails.Status.ContainerStatuses[0].LastTerminationState.String(),
		Count:   1,
		Type:    "AgentStatusInformation",
	}

	return event, nil
}

func (s *Service) GetPodByName(ctx context.Context, name string) (*corev1.Pod, error) {
	pod, err := s.kubernetesClientSet.CoreV1().Pods(s.GetAgentNamespace()).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting pod by name: %w", err)
	}

	return pod, nil
}

func BuildLocalConfig() (*rest.Config, error) {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func IsLocalEnvironment() bool {
	val, ok := os.LookupEnv("ENVIRONMENT")
	if ok && val == "local" {
		return true
	}

	return false
}
