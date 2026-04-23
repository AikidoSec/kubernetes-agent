package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/controllers/openshift"
	"aikidoSec.kubernetesAgent/internal/controllers/traefik"
	internalhttp "aikidoSec.kubernetesAgent/internal/http"
	httpcontrollers "aikidoSec.kubernetesAgent/internal/http/controllers"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/sbom"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/imagescache"
	"aikidoSec.kubernetesAgent/pkg/models"
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

const (
	defaultAgentVersion = "1.0.0"
)

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
	if isLocalEnvironment() {
		cfg, err = buildLocalConfig()
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

func (s *Service) startHeartbeat() {
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
				_, _ = s.sendHeartbeat(ctx)
			case <-s.heartbeatStopChan:
				close(s.heartbeatStopChan)
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Service) stopHeartbeat() {
	s.heartbeatStopChan <- struct{}{}
}

func (s *Service) Close(ctx context.Context) {
	s.stopHeartbeat()

	if err := s.assetsOutputClient.Close(ctx); err != nil {
		s.logger.ReportError(ctx, err, "error closing assets output client", "managerError")
	}
}

// sendHeartbeat sends a heartbeat to the management server and processes the response
func (s *Service) sendHeartbeat(ctx context.Context) (models.HeartbeatResponse, error) {
	metrics := models.Metrics{}
	if s.metricClient != nil {
		agentMetrics, _ := s.getAgentMetrics(ctx)
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
	agentVersion, helmChartsVersion, err := s.getDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context at heartbeat", "managerError")
	}

	sbomCollectorVersion := s.GetSBOMCollectorVersion()
	if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err = loadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
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
		AgentPodName:       s.GetAgentPodName(),
		AgentNamespace:     s.GetAgentNamespace(),
	})
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending heartbeat", "managerError")
		return models.HeartbeatResponse{}, err
	}

	// If the token has changed, update it in the service, output clients and in the agent Kubernetes secret
	if s.GetAPIToken() != resp.Token && resp.Token != "" {
		s.logger.LogInfo("API token updated from heartbeat response")
		if err := s.updateAPIToken(ctx, resp.Token); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent API token", "managerError")
			return resp, err
		}
	}

	if s.GetAutoUpdateEnabled() {
		// If the agent version has changed, update the deployment with the new image version which will also trigger a restart
		if s.GetAgentVersion() != resp.Cluster.DesiredAgentVersion {
			s.logger.LogInfo("agent version updated from heartbeat response", "current version", s.GetAgentVersion(), "new version", resp.Cluster.DesiredAgentVersion)
			if err := s.updateAgentVersion(ctx, resp.Cluster.DesiredAgentVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating agent version", "managerError")
				return resp, err
			}
			s.SetAgentVersion(resp.Cluster.DesiredAgentVersion)
		}
	}

	// If the namespace filter has changed, restart the agent to re-create the watchers with the new filters
	excludedChanged := !slices.Equal(s.GetExcludedNamespaces(), resp.Cluster.ExcludedNamespaces)
	includedChanged := !slices.Equal(s.GetIncludedNamespaces(), resp.Cluster.IncludedNamespaces)
	if excludedChanged || includedChanged {
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			s.logger.LogInfo("namespace filter changed, restarting sbom collector")
			if err := s.restartSBOMCollector(ctx); err != nil {
				s.logger.ReportError(ctx, err, "error restarting sbom collector", "managerError")
			}
		}

		s.logger.LogInfo("namespace filter changed, restarting agent")
		if err := s.restartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetExcludedNamespaces(resp.Cluster.ExcludedNamespaces)
		s.SetIncludedNamespaces(resp.Cluster.IncludedNamespaces)
	}

	monitoredResourcesGVKs := make([]string, 0, len(resp.MonitoredResources))
	for _, gvk := range resp.MonitoredResources {
		monitoredResourcesGVKs = append(monitoredResourcesGVKs, gvk.String())
	}

	// If the monitored resources have changed, restart the agent to re-create the watchers with the new configuration
	if !slices.Equal(s.GetMonitoredResources(), monitoredResourcesGVKs) {
		s.logger.LogInfo("monitored resources changed, restarting agent")
		if err := s.restartDeployment(ctx, s.GetAgentName()); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
		s.SetMonitoredResources(monitoredResourcesGVKs)
	}

	// If the SBOM collector enabled state has changed, update the deployment/daemonset accordingly
	if s.IsSBOMCollectorEnabled() != resp.Cluster.SBOMCollectorEnabled {
		s.logger.LogInfo("sbom collector enabled state changed from heartbeat response", "current state", s.IsSBOMCollectorEnabled(), "new state", resp.Cluster.SBOMCollectorEnabled)
		if err := s.configureSBOMCollector(ctx, resp.Cluster.SBOMCollectorEnabled, s.IsChartsSBOMCollectorEnabled()); err != nil {
			s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
			return resp, err
		}
		s.SetSBOMCollectorEnabled(resp.Cluster.SBOMCollectorEnabled)

		// If the SBOM collector was enabled, load the scanned images from the API server into the cache and set the deployed collector version.
		if s.IsChartsSBOMCollectorEnabled() && s.IsSBOMCollectorEnabled() {
			// Load the SBOM collector version from the deployment labels
			sbomCollectorVersion, err := loadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
			if err != nil {
				s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
			}
			s.SetSBOMCollectorVersion(sbomCollectorVersion)
			// Load the scanned images cache
			collectorScannedImages, err := s.listCollectorScannedImages(ctx)
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
			if err := s.updateSBOMCollectorVersion(ctx, resp.Cluster.DesiredSBOMCollectorVersion); err != nil {
				s.logger.ReportError(ctx, err, "error updating sbom collector version", "managerError")
			}
			s.SetSBOMCollectorVersion(resp.Cluster.DesiredSBOMCollectorVersion)
		}
	}

	// In case no hash is being received through the heartbeat, assume the cache has not changed to prevent pulling the cache from the cloud after every heartbeat
	if s.IsSBOMCollectorEnabled() && resp.ImageCacheHash != nil {
		if hash, err := s.scannedImagesCache.CalculateHash(); err != nil {
			s.logger.ReportError(ctx, err, "error calculating cache hash", "managerError")
		} else if hash != *resp.ImageCacheHash {
			collectorScannedImages, err := s.listCollectorScannedImages(ctx)
			if err != nil {
				s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
			} else {
				s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
			}

		}
	}

	return resp, nil
}

// sendInitialHeartbeat tries to send the initial heartbeat in order to fetch the configuration.
// If we receive an error, we retry until we receive a valid response or the pod is killed by the startup probe.
func (s *Service) sendInitialHeartbeat(ctx context.Context, clusterIdentifier string, namespaceEventsPayload []byte, helmChartsVersion string) (models.HeartbeatResponse, error) {
	for attempt := 1; ; attempt++ {
		hb, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
			AgentVersion:       s.GetAgentVersion(),
			CollectorVersion:   s.GetSBOMCollectorVersion(),
			IsInitialHeartbeat: true,
			ClusterIdentifier:  clusterIdentifier,
			NamespaceEvents:    string(namespaceEventsPayload),
			HelmChartsVersion:  helmChartsVersion,
			AgentPodName:       s.GetAgentPodName(),
			AgentNamespace:     s.GetAgentNamespace(),
		})

		if err == nil {
			return hb, nil
		}

		s.logger.LogWarning(err, "error while sending initial heartbeat, will retry", "attempt", attempt)
		// Exponential backoff with jitter
		d := rand.IntN(min(5, attempt)) * 5
		time.Sleep(time.Duration(d) * time.Second)
	}
}

func (s *Service) InitializeAgent(ctx context.Context, cfg models.Config, runtimeManager manager.Manager, environmentConfig models.EnvironmentConfig) error {
	// Load the agent and charts versions from the deployment labels
	agentVersion, helmChartsVersion, err := s.getDeploymentAndChartsVersions(ctx, s.GetAgentNamespace(), s.GetAgentName())
	if err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context", "managerError")
		return fmt.Errorf("error loading agent version from context: %w", err)
	}
	s.SetAgentVersion(agentVersion)

	clusterIdentifier, err := s.getClusterIdentifier(ctx)
	if err != nil {
		s.logger.LogWarning(err, "error getting cluster identifier", "managerError")
	}

	// List all events from the agent namespace.
	namespaceEvents, _ := s.listEventsByFieldSelector(ctx, "")
	if namespaceEvents == nil {
		namespaceEvents = []corev1.Event{} // empty slice instead of nil so the payload is `[]` instead of `null`
	}

	// Remove the object metadata to reduce payload size
	for i := range namespaceEvents {
		namespaceEvents[i].ObjectMeta = v1.ObjectMeta{}
	}

	// Generate an artificial event for the agent pod to include its status in the initial heartbeat.
	// This helps us identify potential OOM kills.
	generatedPodEvent, err := s.generateAgentPodEvent(ctx)
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
	hb, err := s.sendInitialHeartbeat(ctx, clusterIdentifier, namespaceEventsPayload, helmChartsVersion)
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending initial heartbeat", "managerError")
		return fmt.Errorf("error sending initial heartbeat: %w", err)
	}

	s.SetExcludedNamespaces(hb.Cluster.ExcludedNamespaces)
	s.SetIncludedNamespaces(hb.Cluster.IncludedNamespaces)

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
	if err := s.configureSBOMCollector(ctx, s.IsSBOMCollectorEnabled(), s.IsChartsSBOMCollectorEnabled()); err != nil {
		s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
	}

	// If the SBOM collector is enabled, load the already scanned images from the API server into the cache and configure the collector.
	if s.IsSBOMCollectorEnabled() && s.IsChartsSBOMCollectorEnabled() {
		// Load the SBOM collector version from the deployment labels
		sbomCollectorVersion, err := loadSBOMCollectorVersion(ctx, s.kubernetesClientSet, s.GetAgentNamespace(), s.GetSBOMCollectorName(), s.GetRunSBOMCollectorAsDaemonSet())
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		}
		s.SetSBOMCollectorVersion(sbomCollectorVersion)

		// Load the scanned images cache
		collectorScannedImages, err := s.listCollectorScannedImages(ctx)
		if err != nil {
			s.logger.ReportError(ctx, err, "error listing scanned images from sbom collector", "managerError")
		}

		if len(collectorScannedImages) > 0 {
			s.scannedImagesCache.LoadFromScannedImages(collectorScannedImages)
		}

		// Load the SBOM collector service account
		sa, err := s.getSBOMCollectorServiceAccount(ctx)
		if err != nil {
			s.logger.ReportError(ctx, err, "error loading sbom collector service account from context", "managerError")
		}
		s.SetSBOMCollectorServiceAccount(sa)
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

	agentClusterRole, err := s.kubernetesClientSet.RbacV1().ClusterRoles().Get(ctx, s.GetAgentName(), v1.GetOptions{})
	if err != nil {
		s.logger.ReportError(ctx, err, "error getting agent cluster role", "managerError")
		return fmt.Errorf("error getting agent cluster role: %w", err)
	}

	restMapper := runtimeManager.GetRESTMapper()

	// Set up the resource watchers based on the monitored resources from the heartbeat
	for _, v := range hb.MonitoredResources {
		createController, err := s.shouldCreateController(serverResourcesGVKs, v, restMapper, agentClusterRole)
		if err != nil {
			s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
			return fmt.Errorf("error checking if controller should be created: %w", err)
		}

		if !createController {
			continue
		}

		watcherSelector := models.WatcherSelector{
			GroupVersionKind: v,
			NamespaceFilter:  predicates.NewNamespaceFilter(s.logger, hb.Cluster.ExcludedNamespaces, hb.Cluster.IncludedNamespaces),
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

	// Check if ImageContentSourcePolicy is available in the cluster
	createICSPController, err := s.shouldCreateController(serverResourcesGVKs, openshift.ImageContentSourcePolicyGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createICSPController {
		s.logger.LogInfo("ImageContentSourcePolicy is available in the cluster")
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

	// Check if ImageDigestMirrorSet is available in the cluster
	createIDMSController, err := s.shouldCreateController(serverResourcesGVKs, openshift.ImageDigestMirrorSetGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createIDMSController {
		s.logger.LogInfo("ImageDigestMirrorSet is available in the cluster")
		s.SetImageMappingEnabled(true)
		// Create an ImageDigestMirrorSet controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageDigestMirrorSetController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageDigestMirrorSet controller", "managerError")
		}
	}

	// Check if ImageTagMirrorSet is available in the cluster
	createITMSController, err := s.shouldCreateController(serverResourcesGVKs, openshift.ImageTagMirrorSetGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createITMSController {
		s.logger.LogInfo("ImageTagMirrorSet is available in the cluster")
		s.SetImageMappingEnabled(true)
		// Create an ImageTagMirrorSet controller that will watch for policy changes and update the agent internal registry mappings.
		if err = (&openshift.ImageTagMirrorSetController{
			AgentState: s.AgentState,
			Logger:     s.logger,
			Client:     runtimeManager.GetClient(),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift ImageTagMirrorSet controller", "managerError")
		}
	}

	// Check if IngressRoute is available in the cluster
	createIngressRouteController, err := s.shouldCreateController(serverResourcesGVKs, traefik.IngressRouteGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if createIngressRouteController {
		s.logger.LogInfo("IngressRoute is available in the cluster")
		if err = (&traefik.IngressRouteController{
			Logger:          s.logger,
			Client:          runtimeManager.GetClient(),
			OutputClient:    assetsClient,
			NamespaceFilter: predicates.NewNamespaceFilter(s.logger, hb.Cluster.ExcludedNamespaces, hb.Cluster.IncludedNamespaces),
			PendingMu:       sync.Mutex{},
			Pending:         make(map[string]time.Time),
		}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
			s.logger.ReportError(ctx, err, "error creating new Traefik IngressRoute controller", "managerError")
		}
	}

	s.startHeartbeat()

	s.logger.LogInfo("starting agent", "version", s.GetAgentVersion(), "excluded_namespaces", hb.Cluster.ExcludedNamespaces, "included_namespaces", hb.Cluster.IncludedNamespaces)

	return nil
}

// updateAPIToken updates the API token in the service, output clients and in the agent Kubernetes secret
func (s *Service) updateAPIToken(ctx context.Context, newToken string) error {
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

func (s *Service) getAgentMetrics(ctx context.Context) (models.ComponentMetrics, error) {
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

func buildLocalConfig() (*rest.Config, error) {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func isLocalEnvironment() bool {
	val, ok := os.LookupEnv("ENVIRONMENT")
	if ok && val == "local" {
		return true
	}

	return false
}
