package manager

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const defaultAgentVersion = "0.1.0"

type Options struct {
	AgentNamespace     string
	PodName            string
	APIToken           string
	ExcludedNamespaces []string
	HeartbeatService   *heartbeat.Service
	AssetsOutputClient *batchclient.BatchClient
	Logger             *logger.Service
}
type Service struct {
	agentVersion        string
	agentNamespace      string
	agentName           string
	apiToken            string
	excludedNamespaces  []string
	heartbeatChan       chan struct{}
	kubernetesClientSet *kubernetes.Clientset
	heartbeatService    *heartbeat.Service
	logger              *logger.Service
	assetsOutputClient  *batchclient.BatchClient
}

func NewService(ctx context.Context, o Options) (*Service, error) {
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

	return &Service{
		apiToken:            o.APIToken,
		agentNamespace:      o.AgentNamespace,
		excludedNamespaces:  o.ExcludedNamespaces,
		agentName:           deploymentName,
		kubernetesClientSet: clientSet,
		heartbeatChan:       make(chan struct{}),
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

	s.heartbeatChan = make(chan struct{})
	ticker := time.NewTicker(s.heartbeatService.GetSendInterval())
	go func() {
		for {
			select {
			case <-ticker.C:
				ctx := context.Background()
				if _, err := s.SendHeartbeat(ctx); err != nil {
					s.logger.LogError(err, "error sending heartbeat")
				}
			case <-s.heartbeatChan:
				close(s.heartbeatChan)
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Service) StopHeartbeat() {
	s.heartbeatChan <- struct{}{}
}

func (s *Service) Close(ctx context.Context) {
	s.StopHeartbeat()

	if err := s.assetsOutputClient.Close(ctx); err != nil {
		s.logger.ReportError(ctx, err, "error closing assets output client", "managerError")
	}
}

// SendHeartbeat sends a heartbeat to the management server and processes the response
func (s *Service) SendHeartbeat(ctx context.Context) (models.HeartbeatResponse, error) {
	resp, err := s.heartbeatService.SendHeartbeat(ctx, s.agentVersion)
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending heartbeat", "managerError")
		return models.HeartbeatResponse{}, err
	}

	// If the token has changed, update it in the service, output clients and in the agent Kubernetes secret
	if s.apiToken != resp.Token && resp.Token != "" {
		s.logger.LogInfo("API token updated from heartbeat response")
		if err := s.UpdateAPIToken(ctx, resp.Token); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent API token", "managerError")
			return resp, err
		}
	}

	// If the agent version has changed, update the deployment with the new image version which will also trigger a restart
	if s.agentVersion != resp.Cluster.DesiredAgentVersion {
		s.logger.LogInfo("agent version updated from heartbeat response", "current version", s.agentVersion, "new version", resp.Cluster.DesiredAgentVersion)
		if err := s.UpdateAgentVersion(ctx, resp.Cluster.DesiredAgentVersion); err != nil {
			s.logger.ReportError(ctx, err, "error updating agent version", "managerError")
			return resp, err
		}
	}

	// If the excluded namespaces have changed, restart the agent to re-create the watchers with the new namespaces filters
	if !slices.Equal(s.excludedNamespaces, resp.Cluster.ExcludedNamespaces) {
		s.logger.LogInfo("excluded namespaces changed, restarting agent")
		if err := s.RestartAgent(ctx); err != nil {
			s.logger.ReportError(ctx, err, "error restarting agent", "managerError")
			return resp, err
		}
	}

	return resp, nil
}

func (s *Service) InitializeAgent(ctx context.Context, cfg models.Config, runtimeManager manager.Manager) error {
	// Load the agent version from the deployment labels
	if err := s.LoadAgentVersionFromContext(ctx); err != nil {
		s.logger.ReportError(ctx, err, "error loading agent version from context", "managerError")
		return fmt.Errorf("error loading agent version from context: %w", err)
	}

	// Send the initial heartbeat to get the monitored resources and agent configuration
	hb, err := s.heartbeatService.SendHeartbeat(ctx, s.agentVersion)
	if err != nil {
		s.logger.ReportError(ctx, err, "error sending initial heartbeat", "managerError")
		return fmt.Errorf("error sending initial heartbeat: %w", err)
	}
	s.excludedNamespaces = hb.Cluster.ExcludedNamespaces

	assetsClient, err := batchclient.NewBatchClient(s.logger.GetLogger(), batchclient.ClientOptions{
		Endpoint:              cfg.APIEndpoint + "/api/assets",
		MaxBatch:              1000,
		FlushEvery:            time.Second * 10,
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
	excludedNamespaces := append(hb.Cluster.ExcludedNamespaces, s.agentNamespace)

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
		}).SetupWithManager(runtimeManager, excludedNamespaces); err != nil {
			s.logger.ReportError(ctx, err, "error creating new watcher", "managerError")
			return fmt.Errorf("error creating watcher (%s): %w", v.String(), err)
		}
	}

	s.StartHeartbeat()

	s.logger.LogInfo("starting agent", "version", s.agentVersion, "excluded_namespaces", excludedNamespaces)

	return nil
}

// LoadAgentVersionFromContext gets the deployment details from the API server and extracts the agent version from the labels
func (s *Service) LoadAgentVersionFromContext(ctx context.Context) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		s.agentVersion = defaultAgentVersion
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.agentNamespace).Get(ctx, s.agentName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return fmt.Errorf("agent version label not found on deployment")
	}
	s.agentVersion = agentVersion

	return nil
}

// RestartAgent fetches the agent deployment and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart of the agent
func (s *Service) RestartAgent(ctx context.Context) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.agentNamespace).Get(ctx, s.agentName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent deployment: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.agentNamespace).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}

	return nil
}

// UpdateAgentVersion updates the agent deployment with a new image version and updates the version labels
func (s *Service) UpdateAgentVersion(ctx context.Context, newVersion string) error {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.agentNamespace).Get(ctx, s.agentName, v1.GetOptions{})
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

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.agentNamespace).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}

	// We're setting the agent version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.agentVersion = newVersion
	return nil
}

// UpdateAPIToken updates the API token in the service, output clients and in the agent Kubernetes secret
func (s *Service) UpdateAPIToken(ctx context.Context, newToken string) error {
	if err := s.updateAgentSecret(ctx, newToken); err != nil {
		return fmt.Errorf("error updating agent secret: %w", err)
	}
	s.apiToken = newToken

	// Set the token for the output clients
	s.assetsOutputClient.SetAPIToken(s.apiToken)
	s.logger.SetAPIToken(s.apiToken)

	// Set the heartbeat service token
	s.heartbeatService.SetAPIToken(s.apiToken)

	return nil
}

// updateAgentSecret identifies the agent secret in Kubernetes using the agent name and namespace and updates the API token
func (s *Service) updateAgentSecret(ctx context.Context, newToken string) error {
	secret, err := s.kubernetesClientSet.CoreV1().Secrets(s.agentNamespace).Get(ctx, s.agentName, v1.GetOptions{})
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

	if _, err := s.kubernetesClientSet.CoreV1().Secrets(s.agentNamespace).Update(ctx, secret, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating agent secret with new API token: %w", err)
	}

	return nil
}
