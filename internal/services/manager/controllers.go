package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/controllers"
	"aikidoSec.kubernetesAgent/internal/controllers/argoproj"
	"aikidoSec.kubernetesAgent/internal/controllers/kong"
	"aikidoSec.kubernetesAgent/internal/controllers/openshift"
	"aikidoSec.kubernetesAgent/internal/controllers/traefik"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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

	if err := s.setupOpenshiftControllers(ctx, serverResourcesGVKs, restMapper, agentClusterRole, runtimeManager); err != nil {
		return err
	}

	if err := s.setupTraefikControllers(ctx, serverResourcesGVKs, restMapper, agentClusterRole, runtimeManager, assetsClient, nsFilter); err != nil {
		return err
	}

	if err := s.setupKongControllers(ctx, serverResourcesGVKs, restMapper, agentClusterRole, runtimeManager, assetsClient, nsFilter); err != nil {
		return err
	}

	return s.setupArgoprojControllers(ctx, serverResourcesGVKs, restMapper, agentClusterRole, runtimeManager, assetsClient, nsFilter)
}

func (s *Service) setupOpenshiftControllers(ctx context.Context, serverResourcesGVKs map[string]struct{}, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole, runtimeManager manager.Manager) error {
	type openshiftController struct {
		gvk     schema.GroupVersionKind
		logName string
		setup   func() error
	}

	osControllers := []openshiftController{
		{
			gvk:     openshift.ImageContentSourcePolicyGVK,
			logName: "ImageContentSourcePolicy",
			setup: func() error {
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
				return (&openshift.ImageTagMirrorSetController{
					AgentState: s.AgentState,
					Logger:     s.logger,
					Client:     runtimeManager.GetClient(),
				}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
	}

	for _, c := range osControllers {
		create, err := s.shouldCreateController(serverResourcesGVKs, c.gvk, restMapper, agentClusterRole)
		if err != nil {
			s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
			return fmt.Errorf("error checking if controller should be created: %w", err)
		}
		if !create {
			continue
		}
		s.logger.LogInfo(c.logName + " is available in the cluster")
		s.SetImageMappingEnabled(true)
		if err := c.setup(); err != nil {
			s.logger.ReportError(ctx, err, "error creating new OpenShift "+c.logName+" controller", "managerError")
		}
	}

	return nil
}

func (s *Service) setupTraefikControllers(ctx context.Context, serverResourcesGVKs map[string]struct{}, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole, runtimeManager manager.Manager, assetsClient *batchclient.BatchClient, nsFilter *predicates.NamespaceFilter) error {
	create, err := s.shouldCreateController(serverResourcesGVKs, traefik.IngressRouteGVK, restMapper, agentClusterRole)
	if err != nil {
		s.logger.ReportError(ctx, err, "error checking if controller should be created", "managerError")
		return fmt.Errorf("error checking if controller should be created: %w", err)
	}
	if !create {
		return nil
	}
	s.logger.LogInfo("IngressRoute is available in the cluster")
	if err := (&traefik.IngressRouteController{
		Logger:          s.logger,
		Client:          runtimeManager.GetClient(),
		OutputClient:    assetsClient,
		NamespaceFilter: nsFilter,
		PendingMu:       sync.Mutex{},
		Pending:         make(map[string]time.Time),
	}).SetupWithManager(runtimeManager, controller.Options{}); err != nil {
		s.logger.ReportError(ctx, err, "error creating new Traefik IngressRoute controller", "managerError")
	}
	return nil
}

func (s *Service) setupKongControllers(ctx context.Context, serverResourcesGVKs map[string]struct{}, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole, runtimeManager manager.Manager, assetsClient *batchclient.BatchClient, nsFilter *predicates.NamespaceFilter) error {
	type entry struct {
		gvk     schema.GroupVersionKind
		logName string
		setup   func() error
	}

	kongControllers := []entry{
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
	}

	for _, c := range kongControllers {
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
			s.logger.ReportError(ctx, err, "error creating new Kong "+c.logName+" controller", "managerError")
		}
	}

	return nil
}

func (s *Service) setupArgoprojControllers(ctx context.Context, serverResourcesGVKs map[string]struct{}, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole, runtimeManager manager.Manager, assetsClient *batchclient.BatchClient, nsFilter *predicates.NamespaceFilter) error {
	type entry struct {
		gvk     schema.GroupVersionKind
		logName string
		setup   func() error
	}

	apController := func() argoproj.Controller {
		return argoproj.NewController(runtimeManager.GetClient(), s.logger, assetsClient, nsFilter)
	}

	argoprojControllers := []entry{
		{
			gvk:     argoproj.ApplicationGVK,
			logName: "ArgoCD Application",
			setup: func() error {
				return (&argoproj.ApplicationController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.AppProjectGVK,
			logName: "ArgoCD AppProject",
			setup: func() error {
				return (&argoproj.AppProjectController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.ApplicationSetGVK,
			logName: "ArgoCD ApplicationSet",
			setup: func() error {
				return (&argoproj.ApplicationSetController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.WorkflowGVK,
			logName: "Argo Workflows Workflow",
			setup: func() error {
				return (&argoproj.WorkflowController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.WorkflowTemplateGVK,
			logName: "Argo Workflows WorkflowTemplate",
			setup: func() error {
				return (&argoproj.WorkflowTemplateController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.CronWorkflowGVK,
			logName: "Argo Workflows CronWorkflow",
			setup: func() error {
				return (&argoproj.CronWorkflowController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.ClusterWorkflowTemplateGVK,
			logName: "Argo Workflows ClusterWorkflowTemplate",
			setup: func() error {
				return (&argoproj.ClusterWorkflowTemplateController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.RolloutGVK,
			logName: "Argo Rollouts Rollout",
			setup: func() error {
				return (&argoproj.RolloutController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.AnalysisTemplateGVK,
			logName: "Argo Rollouts AnalysisTemplate",
			setup: func() error {
				return (&argoproj.AnalysisTemplateController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.ClusterAnalysisTemplateGVK,
			logName: "Argo Rollouts ClusterAnalysisTemplate",
			setup: func() error {
				return (&argoproj.ClusterAnalysisTemplateController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
		{
			gvk:     argoproj.AnalysisRunGVK,
			logName: "Argo Rollouts AnalysisRun",
			setup: func() error {
				return (&argoproj.AnalysisRunController{Controller: apController()}).SetupWithManager(runtimeManager, controller.Options{})
			},
		},
	}

	for _, c := range argoprojControllers {
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
			return fmt.Errorf("error creating %s controller: %w", c.logName, err)
		}
	}

	return nil
}
