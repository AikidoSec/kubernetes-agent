package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strconv"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/manager"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/config"
	"aikidoSec.kubernetesAgent/pkg/models"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultNamespace = "aikido"

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
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

	ns, exists := os.LookupEnv("AGENT_NAMESPACE")
	if !exists {
		ns = defaultNamespace
	}

	podName, exists := os.LookupEnv("POD_NAME")
	if !exists {
		l.Error("POD_NAME environment variable not set")
		os.Exit(1)
	}

	apiPortStr, exists := os.LookupEnv("API_PORT")
	if !exists {
		l.Error("API_PORT environment variable not set")
		os.Exit(1)
	}

	apiPort, err := strconv.Atoi(apiPortStr)
	if err != nil {
		l.Error("invalid API_PORT value", "error", err)
		os.Exit(1)
	}

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

	agentState := models.NewEmptyAgentState()
	agentService, err := manager.NewService(ctx, agentState, manager.Options{
		Logger:                            loggerService,
		AgentNamespace:                    ns,
		PodName:                           podName,
		APIToken:                          cfg.APIToken,
		APIEndpoint:                       cfg.APIEndpoint,
		HeartbeatService:                  heartbeatService,
		ControllerCacheSyncTimeout:        cfg.ControllerCacheSyncTimeout,
		IsSBOMCollectorRunningAsDaemonSet: cfg.RunSBOMCollectorAsDaemonSet,
	})
	if err != nil {
		loggerService.ReportError(ctx, err, "error creating agent service", "agentSetupError")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&corev1.Secret{},
				},
			},
		},
		Cache: cache.Options{
			DefaultTransform: func(obj any) (any, error) {
				obj, err := cache.TransformStripManagedFields()(obj)
				if err != nil {
					return obj, err
				}

				// Remove `kubectl.kubernetes.io/last-applied-configuration` annotation from objects
				if metaObj, ok := obj.(metav1.ObjectMetaAccessor); ok {
					annotations := metaObj.GetObjectMeta().GetAnnotations()
					if annotations != nil {
						delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
						metaObj.GetObjectMeta().SetAnnotations(annotations)
					}
				}

				// Remove data from ConfigMaps
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					cm.BinaryData = nil
				}
				return obj, nil
			},
		},
	})
	if err != nil {
		loggerService.ReportError(ctx, err, "error creating manager", "agentSetupError")
		os.Exit(1)
	}

	if err := agentService.InitializeAgent(ctx, cfg, mgr, apiPort); err != nil {
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
