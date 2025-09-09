package main

import (
	"context"
	"flag"
	"log/slog"
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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultNamespace = "aikido-security"

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

	agentService, err := manager.NewService(ctx, manager.Options{
		Logger:           loggerService,
		AgentNamespace:   ns,
		PodName:          podName,
		APIToken:         cfg.APIToken,
		HeartbeatService: heartbeatService,
	})
	if err != nil {
		l.Error("error creating manager service", "error", err)
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		l.Error("error creating manager", "error", err)
		os.Exit(1)
	}

	if err := agentService.InitializeAgent(ctx, cfg, mgr); err != nil {
		l.Error("error initializing agent", "error", err)
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		l.Error("error adding healthz check", "error", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		l.Error("error adding ready check", "error", err)
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Error("error running manager", "error", err)
		os.Exit(1)
	}
	agentService.Close(ctx)
}
