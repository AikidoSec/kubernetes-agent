package manager

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testNamespace = "test-ns"
	testDSName    = "test-agent-runtime-protection"
)

type heartbeatTestSetup struct {
	chartsEnabled         bool
	initiallyEnabled      bool
	initialRules          []string
	initialExceptions     []models.ThreatDetectionException
	initialEmbeddedRules  string // pre-seeded value of 01-threat-detection-rules.yaml
	initialExceptionsYAML string // pre-seeded value of 02-threat-detection-exceptions.yaml
}

func newServiceForHeartbeatTest(t *testing.T, setup heartbeatTestSetup) (*Service, *fake.Clientset) {
	t.Helper()

	fakeClient := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testDSName,
				Namespace: testNamespace,
				Labels:    map[string]string{"app.kubernetes.io/version": "0.43.0"},
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes-agent-falco-config", Namespace: testNamespace},
			Data:       map[string]string{"rules-override.yaml": ""},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes-agent-falco-rules", Namespace: testNamespace},
			Data: map[string]string{
				"01-threat-detection-rules.yaml": setup.initialEmbeddedRules,
				"02-threat-detection-exceptions.yaml": setup.initialExceptionsYAML,
			},
		},
	)

	state := models.NewEmptyAgentState()
	state.SetInitialValues(
		"test-agent-pod-abc123", testNamespace, "test-agent",
		"", "", "", 0, false, "", false, testDSName,
	)
	state.SetChartsRuntimeProtectionEnabled(setup.chartsEnabled)
	state.SetThreatDetectionEnabled(setup.initiallyEnabled)
	state.SetEnabledThreatRules(setup.initialRules)
	state.SetThreatDetectionExceptions(setup.initialExceptions)

	svc := &Service{
		AgentState:          state,
		kubernetesClientSet: fakeClient,
		logger:              logger.NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
	}
	return svc, fakeClient
}

func getCMKey(t *testing.T, client *fake.Clientset, cmName, key string) string {
	t.Helper()
	cm, err := client.CoreV1().ConfigMaps(testNamespace).Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get configmap %q: %v", cmName, err)
	}
	return cm.Data[key]
}

func daemonSetRestarted(t *testing.T, client *fake.Clientset) bool {
	t.Helper()
	ds, err := client.AppsV1().DaemonSets(testNamespace).Get(context.Background(), testDSName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get daemonset %q: %v", testDSName, err)
	}
	_, ok := ds.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
	return ok
}

func ptrOf[T any](v T) *T { return &v }

func TestHandleThreatDetectionHeartbeat(t *testing.T) {
	ruleA := "Read sensitive file untrusted"
	ruleB := "Write below root"
	oneException := []models.ThreatDetectionException{{
		ID:        1,
		Name:      "suppress myapp",
		RuleNames: []string{ruleA},
		Conditions: []models.ExceptionCondition{
			{Field: "proc.name", Operator: "=", Value: "myapp"},
		},
	}}

	tests := []struct {
		name  string
		setup heartbeatTestSetup
		td    models.ThreatDetectionHeartbeat
		// state assertions
		wantEnabled bool
		wantRules   []string // nil = skip
		// K8s side-effect assertions: nil pointer = skip assertion
		wantRestarted             bool
		wantEmbeddedRulesNonEmpty *bool // true = non-empty written, false = empty/cleared
		wantExceptionsNonEmpty    *bool
	}{
		{
			name:          "charts disabled: early return, no K8s ops regardless of enabled flag",
			setup:         heartbeatTestSetup{chartsEnabled: false},
			td:            models.ThreatDetectionHeartbeat{Enabled: true, Rules: []string{ruleA}},
			wantEnabled:   true, // in-memory state is still updated
			wantRestarted: false,
		},
		{
			name:  "enabling (false→true): writes embedded rules, rebuilds override, restarts",
			setup: heartbeatTestSetup{chartsEnabled: true, initiallyEnabled: false},
			td:    models.ThreatDetectionHeartbeat{Enabled: true, Rules: []string{ruleA}},
			wantEnabled:               true,
			wantRules:                 []string{ruleA},
			wantRestarted:             true,
			wantEmbeddedRulesNonEmpty: ptrOf(true),
		},
		{
			name: "disabling (true→false): clears embedded rules, clears exceptions, and restarts",
			setup: heartbeatTestSetup{
				chartsEnabled:         true,
				initiallyEnabled:      true,
				initialRules:          []string{ruleA},
				initialExceptions:     []models.ThreatDetectionException{{ID: 1, Name: "ex", RuleNames: []string{ruleA}, Conditions: []models.ExceptionCondition{{Field: "proc.name", Operator: "=", Value: "myapp"}}}},
				initialEmbeddedRules:  "existing rules content",
				initialExceptionsYAML: "existing exceptions content",
			},
			td:                        models.ThreatDetectionHeartbeat{Enabled: false},
			wantEnabled:               false,
			wantRules:                 []string{},
			wantRestarted:             true,
			wantEmbeddedRulesNonEmpty: ptrOf(false),
			wantExceptionsNonEmpty:    ptrOf(false),
		},
		{
			name:  "enabling (false→true) with exceptions: populates rules, exceptions, and restarts",
			setup: heartbeatTestSetup{chartsEnabled: true, initiallyEnabled: false},
			td: models.ThreatDetectionHeartbeat{
				Enabled:    true,
				Rules:      []string{ruleA},
				Exceptions: ptrOf(oneException),
			},
			wantEnabled:               true,
			wantRules:                 []string{ruleA},
			wantRestarted:             true,
			wantEmbeddedRulesNonEmpty: ptrOf(true),
			wantExceptionsNonEmpty:    ptrOf(true),
		},
		{
			name: "steady-state disabled: no K8s ops",
			setup: heartbeatTestSetup{
				chartsEnabled:    true,
				initiallyEnabled: false,
			},
			td:            models.ThreatDetectionHeartbeat{Enabled: false},
			wantEnabled:   false,
			wantRules:     []string{},
			wantRestarted: false,
		},
		{
			name: "steady-state enabled, rules changed: updates override and restarts",
			setup: heartbeatTestSetup{
				chartsEnabled:    true,
				initiallyEnabled: true,
				initialRules:     []string{ruleA},
			},
			td:            models.ThreatDetectionHeartbeat{Enabled: true, Rules: []string{ruleA, ruleB}},
			wantEnabled:   true,
			wantRules:     []string{ruleA, ruleB},
			wantRestarted: true,
		},
		{
			name: "steady-state enabled, exceptions changed: updates exceptions and restarts",
			setup: heartbeatTestSetup{
				chartsEnabled:    true,
				initiallyEnabled: true,
				initialRules:     []string{ruleA},
			},
			td: models.ThreatDetectionHeartbeat{
				Enabled:    true,
				Rules:      []string{ruleA},
				Exceptions: ptrOf(oneException),
			},
			wantEnabled:            true,
			wantRules:              []string{ruleA},
			wantRestarted:          true,
			wantExceptionsNonEmpty: ptrOf(true),
		},
		{
			name: "steady-state enabled, nothing changed: no restart",
			setup: heartbeatTestSetup{
				chartsEnabled:    true,
				initiallyEnabled: true,
				initialRules:     []string{ruleA},
			},
			td: models.ThreatDetectionHeartbeat{
				Enabled:    true,
				Rules:      []string{ruleA},
				Exceptions: ptrOf([]models.ThreatDetectionException{}),
			},
			wantEnabled:   true,
			wantRules:     []string{ruleA},
			wantRestarted: false,
		},
		{
			name: "steady-state enabled, nil exceptions (server error): no exception change, no restart",
			setup: heartbeatTestSetup{
				chartsEnabled:    true,
				initiallyEnabled: true,
				initialRules:     []string{ruleA},
			},
			td: models.ThreatDetectionHeartbeat{
				Enabled:    true,
				Rules:      []string{ruleA},
				Exceptions: nil,
			},
			wantEnabled:   true,
			wantRules:     []string{ruleA},
			wantRestarted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup.initialRules == nil {
				tt.setup.initialRules = []string{}
			}
			if tt.setup.initialExceptions == nil {
				tt.setup.initialExceptions = []models.ThreatDetectionException{}
			}

			svc, fakeClient := newServiceForHeartbeatTest(t, tt.setup)
			svc.handleThreatDetectionHeartbeat(context.Background(), tt.td)

			if got := svc.IsThreatDetectionEnabled(); got != tt.wantEnabled {
				t.Errorf("IsThreatDetectionEnabled() = %v, want %v", got, tt.wantEnabled)
			}

			if tt.wantRules != nil {
				if got := svc.GetEnabledThreatRules(); !slices.Equal(got, tt.wantRules) {
					t.Errorf("GetEnabledThreatRules() = %v, want %v", got, tt.wantRules)
				}
			}

			if got := daemonSetRestarted(t, fakeClient); got != tt.wantRestarted {
				t.Errorf("daemonset restarted = %v, want %v", got, tt.wantRestarted)
			}

			if tt.wantEmbeddedRulesNonEmpty != nil {
				got := getCMKey(t, fakeClient, "kubernetes-agent-falco-rules", "01-threat-detection-rules.yaml")
				if *tt.wantEmbeddedRulesNonEmpty && got == "" {
					t.Error("expected embedded rules to be written (non-empty), got empty")
				}
				if !*tt.wantEmbeddedRulesNonEmpty && got != "" {
					t.Errorf("expected embedded rules to be cleared (empty), got non-empty content")
				}
			}

			if tt.wantExceptionsNonEmpty != nil {
				got := getCMKey(t, fakeClient, "kubernetes-agent-falco-rules", "02-threat-detection-exceptions.yaml")
				if *tt.wantExceptionsNonEmpty && got == "" {
					t.Error("expected exceptions to be written (non-empty), got empty")
				}
				if !*tt.wantExceptionsNonEmpty && got != "" {
					t.Errorf("expected exceptions to be cleared (empty), got non-empty content")
				}
			}
		})
	}
}
