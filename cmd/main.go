package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/manager"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/config"
	"aikidoSec.kubernetesAgent/pkg/models"

	"github.com/go-logr/logr"
	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
	openshiftconfigv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(operatorv1alpha1.Install(scheme))
	utilruntime.Must(openshiftconfigv1.Install(scheme))
	utilruntime.Must(kedav1alpha1.AddToScheme(scheme))
}

// nolint:gocyclo
func main() {
	var probeAddr, configFile string
	var heartbeatIntervalSeconds int
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&configFile, "config", "/etc/kubernetes-agent/config.yaml", "The path to the configuration file.")
	flag.IntVar(&heartbeatIntervalSeconds, "heartbeat-interval", 30, "The interval in seconds between heartbeats.")
	flag.Parse()

	// Silence controller-runtime logs
	ctrl.SetLogger(logr.New(log.NullLogSink{}))

	ctx := context.Background()
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Load the config from the file passed as argument
	cfg, err := config.ParseConfigFromFile(configFile)
	if err != nil {
		l.Error("error loading config", "error", err)
		os.Exit(1)
	}

	heartbeatService := heartbeat.NewService(cfg.APIEndpoint, cfg.APIToken, time.Second*time.Duration(heartbeatIntervalSeconds))
	errorsClient, err := batchclient.NewBatchClient(l, batchclient.ClientOptions{
		Endpoint:              cfg.APIEndpoint + "/api/errors",
		MaxBatch:              1000,
		FlushEvery:            time.Second * 10,
		MaxConcurrentRequests: 10,
		CompressionEnabled:    true,
		Token:                 cfg.APIToken,
		HeartbeatService:      heartbeatService,
	})
	if err != nil {
		l.Error("error creating batch client", "error", err)
		os.Exit(1)
	}
	loggerService := logger.NewService(l, errorsClient)
	defer loggerService.Close(ctx)

	envCfg, err := config.ParseEnvironmentConfigs()
	if err != nil {
		loggerService.ReportError(ctx, err, "error parsing environment configs", "agentSetupError")
		os.Exit(1)
	}

	agentState := models.NewEmptyAgentState()
	agentService, err := manager.NewService(ctx, agentState, manager.Options{
		Logger:                            loggerService,
		AgentNamespace:                    envCfg.Namespace,
		AgentName:                         envCfg.AgentName,
		ConfigSecretName:                  envCfg.ConfigSecretName,
		AgentPodName:                      envCfg.AgentPodName,
		APIToken:                          cfg.APIToken,
		APIEndpoint:                       cfg.APIEndpoint,
		HeartbeatService:                  heartbeatService,
		ControllerCacheSyncTimeout:        envCfg.ControllerCacheSyncTimeout,
		IsSBOMCollectorRunningAsDaemonSet: envCfg.RunSBOMCollectorAsDaemonSet,
		AutoUpdateEnabled:                 envCfg.AutoUpdateEnabled,
	})
	if err != nil {
		loggerService.ReportError(ctx, err, "error creating agent service", "agentSetupError")
		os.Exit(1)
	}

	agentStartTime := time.Now()
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		Metrics:                metricsserver.Options{BindAddress: fmt.Sprintf(":%d", envCfg.MetricsPort)},
		Cache: cache.Options{
			DefaultTransform: func(obj any) (any, error) {
				metaObj, err := meta.Accessor(obj)
				if err != nil {
					return obj, nil
				}

				annotations := metaObj.GetAnnotations()
				if annotations != nil {
					// Remove `kubectl.kubernetes.io/last-applied-configuration` annotation
					delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
					metaObj.SetAnnotations(annotations)
				}

				// Remove managed fields
				if metaObj.GetManagedFields() != nil {
					metaObj.SetManagedFields(nil)
				}

				// Remove binary data from ConfigMaps
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					cm.BinaryData = nil
				}

				// Skip caching Jobs older than 5 days
				if job, ok := obj.(*batchv1.Job); ok {
					if job.CreationTimestamp.Time.Before(agentStartTime.AddDate(0, 0, -5)) {
						return nil, nil
					}
				}

				if pod, ok := obj.(*corev1.Pod); ok {
					// Skip caching Pods that are in Succeeded or Failed phase
					if (pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed) && pod.DeletionTimestamp.IsZero() && pod.CreationTimestamp.Time.Before(agentStartTime) {
						return nil, nil
					}
				}
				return obj, nil
			},
		},
	})
	if err != nil {
		loggerService.ReportError(ctx, err, "error creating manager", "agentSetupError")
		os.Exit(1)
	}

	if err := agentService.InitializeAgent(ctx, cfg, mgr, envCfg); err != nil {
		loggerService.ReportError(ctx, err, "error initializing agent", "agentSetupError")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		loggerService.ReportError(ctx, err, "error adding healthz check", "agentSetupError")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		loggerService.ReportError(ctx, err, "error adding readyz check", "agentSetupError")
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		loggerService.ReportError(ctx, err, "error starting manager", "agentSetupError")
		os.Exit(1)
	}
	agentService.Close(ctx)
}
