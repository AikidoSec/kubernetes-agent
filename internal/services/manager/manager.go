package manager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
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
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"gopkg.in/yaml.v3"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var noHostErrorMessage = "no such host"

const (
	defaultAgentVersion = "1.0.0"

	sbomCollectorOwnerName = "aikido-kubernetes-sbom-collector"
)

type Options struct {
	AgentNamespace                    string
	PodName                           string
	APIToken                          string
	APIEndpoint                       string
	ExcludedNamespaces                []string
	HeartbeatService                  *heartbeat.Service
	AssetsOutputClient                *batchclient.BatchClient
	Logger                            *logger.Service
	ControllerCacheSyncTimeout        time.Duration
	IsSBOMCollectorRunningAsDaemonSet bool
}
type Service struct {
	*models.AgentState
	logger *logger.Service
	// Channel to stop the heartbeat goroutine.
	heartbeatStopChan   chan struct{}
	kubernetesClientSet *kubernetes.Clientset
	heartbeatService    *heartbeat.Service
	assetsOutputClient  *batchclient.BatchClient
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

	// Extract the agent name from the Pod name by removing the last two components (replicaset name and random suffix)
	agentNameComponents := strings.Split(o.PodName, "-")
	if len(agentNameComponents) < 2 {
		o.Logger.ReportError(ctx, fmt.Errorf("invalid agent name: %s", o.PodName), "invalid agent name", "managerError")
		return nil, fmt.Errorf("invalid agent name: %s", o.PodName)
	}
	deploymentName := strings.Join(agentNameComponents[:len(agentNameComponents)-2], "-")

	// Load the agent version from the deployment labels
	agentVersion, err := LoadDeploymentVersion(ctx, clientSet, o.AgentNamespace, deploymentName)
	if err != nil {
		o.Logger.ReportError(ctx, err, "error loading agent version from context", "managerError")
		return nil, fmt.Errorf("error loading agent version from context: %w", err)
	}

	sbomCollectorVersion, err := LoadSBOMCollectorVersion(ctx, clientSet, o.AgentNamespace, sbomCollectorOwnerName, o.IsSBOMCollectorRunningAsDaemonSet)
	if err != nil {
		o.Logger.ReportError(ctx, err, "error loading sbom collector version from context", "managerError")
		return nil, fmt.Errorf("error loading sbom collector version from context: %w", err)
	}

	// Initialize the agent state with all values from options and context
	agentState.SetInitialValues(agentVersion, o.AgentNamespace, deploymentName, o.APIToken, o.APIEndpoint, o.ControllerCacheSyncTimeout, o.IsSBOMCollectorRunningAsDaemonSet, sbomCollectorVersion)

	return &Service{
		AgentState:          agentState,
		heartbeatStopChan:   make(chan struct{}),
		kubernetesClientSet: clientSet,
		heartbeatService:    o.HeartbeatService,
		logger:              o.Logger,
		assetsOutputClient:  o.AssetsOutputClient,
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
	resp, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       s.GetAgentVersion(),
		IsInitialHeartbeat: false,
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

	// If the agent version has changed, update the deployment with the new image version which will also trigger a restart
	if s.GetAgentVersion() != resp.Cluster.DesiredAgentVersion {
		s.logger.LogInfo("agent version updated from heartbeat response", "current version", s.GetAgentVersion(), "new version", resp.Cluster.DesiredAgentVersion)
		if err := s.UpdateAgentVersion(ctx, resp.Cluster.DesiredAgentVersion); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent version", "managerError")
			return resp, err
		}
	}

	// If the excluded namespaces have changed, restart the agent to re-create the watchers with the new namespaces filters
	if !slices.Equal(s.GetExcludedNamespaces(), resp.Cluster.ExcludedNamespaces) {
		if s.IsSBOMCollectorEnabled() {
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
		if err := s.ConfigureSBOMCollector(ctx, resp.Cluster.SBOMCollectorEnabled); err != nil {
			s.logger.ReportError(ctx, err, "error configuring sbom collector", "managerError")
			return resp, err
		}
	}

	// If the SBOM collector version has changed, update it in the service state
	if s.GetSBOMCollectorVersion() != resp.Cluster.DesiredSBOMCollectorVersion {
		s.logger.LogInfo("sbom collector version updated from heartbeat response", "current version", s.GetSBOMCollectorVersion(), "new version", resp.Cluster.DesiredSBOMCollectorVersion)
		if err := s.UpdateSBOMCollectorVersion(ctx, resp.Cluster.DesiredSBOMCollectorVersion); err != nil {
			s.logger.ReportError(ctx, err, "error updating sbom collector version", "managerError")
		}
	}

	return resp, nil
}

func (s *Service) InitializeAgent(ctx context.Context, cfg models.Config, runtimeManager manager.Manager) error {
	clusterIdentifier, err := s.GetClusterIdentifier(ctx)
	if err != nil {
		s.logger.LogWarning(err, "error getting cluster identifier", "managerError")
	}

	// Send the initial heartbeat to get the monitored resources and agent configuration
	hb, err := s.heartbeatService.SendHeartbeat(ctx, models.HeartbeatPayload{
		AgentVersion:       s.GetAgentVersion(),
		IsInitialHeartbeat: true,
		ClusterIdentifier:  clusterIdentifier,
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

	sbomController := httpcontrollers.NewSBOMController(s.logger.GetLogger(), sbom.NewService(s.logger, s.AgentState, imagescache.NewImagesCache()))

	// Initialize the HTTP server that communicates with other components (e.g. the SBOM collector)
	s.SetSBOMCollectorEnabled(hb.Cluster.SBOMCollectorEnabled)
	go func() {
		if err := internalhttp.ListenAndServe(ctx, s.logger.GetLogger(), 81, sbomController); err != nil {
			s.logger.ReportError(ctx, err, "error starting sbom controller", "managerError")
		}
	}()

	watcherOptions := controller.Options{
		CacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
	}

	// Set up the resource watchers based on the monitored resources from the heartbeat
	for _, v := range hb.MonitoredResources {
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
			Pending:      make(map[string]struct{}),
		}).SetupWithManager(runtimeManager, watcherOptions); err != nil {
			s.logger.ReportError(ctx, err, "error creating new watcher", "managerError")
			return fmt.Errorf("error creating watcher (%s): %w", v.String(), err)
		}
	}

	s.StartHeartbeat()

	s.logger.LogInfo("starting agent", "version", s.GetAgentVersion(), "excluded_namespaces", excludedNamespaces)

	return nil
}

// RestartDeployment fetches the deployment and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) RestartDeployment(ctx context.Context, deploymentName string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
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
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
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
	secret, err := s.kubernetesClientSet.CoreV1().Secrets(s.GetAgentNamespace()).Get(ctx, s.GetAgentName(), v1.GetOptions{})
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

func (s *Service) ConfigureSBOMCollector(ctx context.Context, enabled bool) error {
	if s.IsSBOMCollectorRunningAsDaemonSet() {
		return s.configureSBOMCollectorDaemonSet(ctx, enabled)
	}

	return s.configureSBOMCollectorDeployment(ctx, enabled)
}

func (s *Service) configureSBOMCollectorDaemonSet(ctx context.Context, enabled bool) error {
	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, sbomCollectorOwnerName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if enabled {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	} else {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{
			"aikidoSec.com/disable-sbom-collector": "true",
		}
	}

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, ds, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector daemonset: %w", err)
	}
	return nil
}

func (s *Service) configureSBOMCollectorDeployment(ctx context.Context, enabled bool) error {
	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, sbomCollectorOwnerName, v1.GetOptions{})
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
	if s.IsSBOMCollectorRunningAsDaemonSet() {
		return s.RestartDaemonSet(ctx, sbomCollectorOwnerName)
	}

	return s.RestartDeployment(ctx, sbomCollectorOwnerName)
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
	if s.IsSBOMCollectorRunningAsDaemonSet() {
		return s.UpdateSBOMCollectorDaemonSetVersion(ctx, newVersion)
	}

	return s.UpdateSBOMCollectorDeploymentVersion(ctx, newVersion)
}

// UpdateSBOMCollectorDeploymentVersion updates the sbom collector deployment with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDeploymentVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, sbomCollectorOwnerName, v1.GetOptions{})
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

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, sbomCollectorOwnerName, v1.GetOptions{})
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
