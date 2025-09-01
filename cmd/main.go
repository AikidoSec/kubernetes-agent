package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/internal/services/manager"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/config"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const defaultNamespace = "aikido-security"

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// nolint:gocyclo
func main() {
	var probeAddr, configFile string
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&configFile, "config", "/etc/kubernetes-agent/config.yaml", "The path to the configuration file.")
	flag.Parse()

	ctx := context.Background()

	// Setup the logger
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ns, exists := os.LookupEnv("AGENT_NAMESPACE")
	if !exists {
		ns = defaultNamespace
	}

	agentName, exists := os.LookupEnv("AGENT_NAME")
	if !exists {
		setupLog.Error(fmt.Errorf("missing agent name from env"), "unable to get agent name from env")
		os.Exit(1)
	}

	// Load the config from the file passed as argument
	cfg, err := config.ParseConfigFromFile(configFile)
	if err != nil {
		setupLog.Error(err, "unable to load config")
		os.Exit(1)
	}

	heartbeatService := heartbeat.NewService(cfg.APIEndpoint, cfg.APIToken, time.Second*2)
	errorsClient, err := batchclient.NewBatchClient(setupLog, batchclient.ClientOptions{
		Endpoint:              cfg.APIEndpoint + "/errors",
		MaxBatch:              1000,
		FlushEvery:            time.Second * 10,
		MaxConcurrentRequests: 10,
		CompressionEnabled:    true,
		Token:                 cfg.APIToken,
		HeartbeatService:      heartbeatService,
	})
	if err != nil {
		setupLog.Error(err, "unable to create assets client")
		os.Exit(1)
	}
	loggerService := logger.NewService(setupLog, errorsClient)

	agentService, err := manager.NewService(manager.Options{
		Logger:           loggerService,
		AgentNamespace:   ns,
		PodName:          agentName,
		APIToken:         cfg.APIToken,
		HeartbeatService: heartbeatService,
	})
	if err != nil {
		setupLog.Error(err, "unable to create agent services")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := agentService.InitializeAgent(ctx, cfg, mgr); err != nil {
		setupLog.Error(err, "error initializing agent")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
	agentService.StopHeartbeat()
}
