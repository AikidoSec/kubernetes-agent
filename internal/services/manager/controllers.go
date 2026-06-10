package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/controllers/argoproj"
	"aikidoSec.kubernetesAgent/internal/controllers/keda"
	"aikidoSec.kubernetesAgent/internal/controllers/kong"
	"aikidoSec.kubernetesAgent/internal/controllers/openshift"
	"aikidoSec.kubernetesAgent/internal/controllers/traefik"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// setupControllers discovers available cluster resources, checks RBAC permissions, and
// creates a controller for every GVK the agent is configured to watch.
func (s *Service) setupControllers(ctx context.Context, runtimeManager manager.Manager, hb models.HeartbeatResponse, assetsClient *batchclient.BatchClient) error {
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
	nsFilter := predicates.NewNamespaceFilter(s.logger, hb.Cluster.ExcludedNamespaces, hb.Cluster.IncludedNamespaces)

	// Set up the resource watchers based on the monitored resources from the heartbeat.
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
			NamespaceFilter:  nsFilter,
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

	type vendorController struct {
		gvk     schema.GroupVersionKind
		logName string
		setup   func() error
	}

	vendorControllers := []vendorController{
		{
			gvk:     openshift.ImageContentSourcePolicyGVK,
			logName: "ImageContentSourcePolicy",
			setup: func() error {
				s.SetImageMappingEnabled(true)
				return (&openshift.ImageContentSourcePolicyController{
					AgentState: s.AgentState,
					Logger:     s.logger,
					Client:     runtimeManager.GetClient(),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     openshift.ImageDigestMirrorSetGVK,
			logName: "ImageDigestMirrorSet",
			setup: func() error {
				s.SetImageMappingEnabled(true)
				return (&openshift.ImageDigestMirrorSetController{
					AgentState: s.AgentState,
					Logger:     s.logger,
					Client:     runtimeManager.GetClient(),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     openshift.ImageTagMirrorSetGVK,
			logName: "ImageTagMirrorSet",
			setup: func() error {
				s.SetImageMappingEnabled(true)
				return (&openshift.ImageTagMirrorSetController{
					AgentState: s.AgentState,
					Logger:     s.logger,
					Client:     runtimeManager.GetClient(),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     traefik.IngressRouteGVK,
			logName: "IngressRoute",
			setup: func() error {
				return (&traefik.IngressRouteController{
					Logger:          s.logger,
					Client:          runtimeManager.GetClient(),
					OutputClient:    assetsClient,
					NamespaceFilter: nsFilter,
					PendingMu:       sync.Mutex{},
					Pending:         make(map[string]time.Time),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     kong.KongServiceGVK,
			logName: "KongService",
			setup: func() error {
				return (&kong.KongServiceController{
					Logger:          s.logger,
					Client:          runtimeManager.GetClient(),
					OutputClient:    assetsClient,
					NamespaceFilter: nsFilter,
					PendingMu:       sync.Mutex{},
					Pending:         make(map[string]time.Time),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     kong.KongRouteGVK,
			logName: "KongRoute",
			setup: func() error {
				return (&kong.KongRouteController{
					Logger:          s.logger,
					Client:          runtimeManager.GetClient(),
					OutputClient:    assetsClient,
					NamespaceFilter: nsFilter,
					PendingMu:       sync.Mutex{},
					Pending:         make(map[string]time.Time),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.ApplicationGVK,
			logName: "ArgoCD Application",
			setup: func() error {
				return (&argoproj.ApplicationController{
					Controller: argoproj.NewController(runtimeManager.GetClient(), s.logger, assetsClient, nsFilter),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.RolloutGVK,
			logName: "Argo Rollouts Rollout",
			setup: func() error {
				return (&argoproj.RolloutController{
					Controller: argoproj.NewController(runtimeManager.GetClient(), s.logger, assetsClient, nsFilter),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     keda.ScaledJobGVK,
			logName: "ScaledJob",
			setup: func() error {
				return (&keda.ScaledJobController{
					Logger:          s.logger,
					Client:          runtimeManager.GetClient(),
					OutputClient:    assetsClient,
					NamespaceFilter: nsFilter,
					PendingMu:       sync.Mutex{},
					Pending:         make(map[string]time.Time),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
	}

	for _, c := range vendorControllers {
		create, err := s.shouldCreateController(serverResourcesGVKs, c.gvk, restMapper, agentClusterRole)
		if err != nil {
			s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
			return fmt.Errorf("error checking if controller should be created: %w", err)
		}
		if !create {
			continue
		}
		s.logger.LogInfo(c.logName + " is available in the cluster")
		if err := c.setup(); err != nil {
			s.logger.ReportError(ctx, err, "error creating "+c.logName+" controller", "managerError")
		}
	}

	return nil
}
