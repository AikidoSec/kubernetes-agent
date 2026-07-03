package manager

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func newServiceForFalcoVersionTest(t *testing.T, objects ...runtime.Object) *Service {
	t.Helper()
	fakeClient := fake.NewClientset(objects...)

	state := models.NewEmptyAgentState()
	state.SetInitialValues(
		"test-agent-pod-abc123", testNamespace, "test-agent",
		"", "", "", 0, false, "", false, testDSName,
	)

	return &Service{
		AgentState:          state,
		kubernetesClientSet: fakeClient,
		logger:              logger.NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
	}
}

func newFalcoDaemonSet(mainImages, initImages []string, currentVersion string) *appsv1.DaemonSet {
	mainContainers := make([]corev1.Container, len(mainImages))
	for i, img := range mainImages {
		mainContainers[i] = corev1.Container{Name: fmt.Sprintf("c-%d", i), Image: img}
	}
	initContainers := make([]corev1.Container, len(initImages))
	for i, img := range initImages {
		initContainers[i] = corev1.Container{Name: fmt.Sprintf("init-%d", i), Image: img}
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testDSName,
			Namespace: testNamespace,
			Labels:    map[string]string{"app.kubernetes.io/version": currentVersion},
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app.kubernetes.io/version": currentVersion},
				},
				Spec: corev1.PodSpec{
					Containers:     mainContainers,
					InitContainers: initContainers,
				},
			},
		},
	}
}

func TestUpdateFalcoVersion(t *testing.T) {
	const newVersion = "0.44.0"

	t.Run("updates tagged images in main and init containers and sets version labels", func(t *testing.T) {
		ds := newFalcoDaemonSet(
			[]string{"falcosecurity/falco:0.43.0"},
			[]string{"falcosecurity/falco-driver-loader:0.43.0"},
			"0.43.0",
		)
		svc := newServiceForFalcoVersionTest(t, ds)

		applied, err := svc.UpdateFalcoVersion(context.Background(), newVersion)
		if err != nil {
			t.Fatalf("UpdateFalcoVersion() error = %v", err)
		}
		if !applied {
			t.Fatal("UpdateFalcoVersion() applied = false, want true")
		}

		got, err := svc.kubernetesClientSet.AppsV1().DaemonSets(testNamespace).Get(context.Background(), testDSName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get daemonset: %v", err)
		}
		if got.Spec.Template.Spec.Containers[0].Image != "falcosecurity/falco:0.44.0" {
			t.Errorf("main container image = %q, want falcosecurity/falco:0.44.0", got.Spec.Template.Spec.Containers[0].Image)
		}
		if got.Spec.Template.Spec.InitContainers[0].Image != "falcosecurity/falco-driver-loader:0.44.0" {
			t.Errorf("init container image = %q, want falcosecurity/falco-driver-loader:0.44.0", got.Spec.Template.Spec.InitContainers[0].Image)
		}
		if got.Labels["app.kubernetes.io/version"] != newVersion {
			t.Errorf("daemonset version label = %q, want %q", got.Labels["app.kubernetes.io/version"], newVersion)
		}
		if got.Spec.Template.Labels["app.kubernetes.io/version"] != newVersion {
			t.Errorf("pod template version label = %q, want %q", got.Spec.Template.Labels["app.kubernetes.io/version"], newVersion)
		}
		if svc.GetFalcoVersion() != newVersion {
			t.Errorf("agent state falco version = %q, want %q", svc.GetFalcoVersion(), newVersion)
		}
	})

	t.Run("returns error and leaves agent state untouched when daemonset is missing", func(t *testing.T) {
		svc := newServiceForFalcoVersionTest(t)
		svc.SetFalcoVersion("0.43.0")

		if _, err := svc.UpdateFalcoVersion(context.Background(), newVersion); err == nil {
			t.Fatal("UpdateFalcoVersion() with missing daemonset: expected error, got nil")
		}
		if svc.GetFalcoVersion() != "0.43.0" {
			t.Errorf("agent state falco version = %q, want unchanged %q", svc.GetFalcoVersion(), "0.43.0")
		}
	})

	t.Run("skips digest-pinned images", func(t *testing.T) {
		ds := newFalcoDaemonSet(
			[]string{"falcosecurity/falco@sha256:0123456789abcdef"},
			nil,
			"0.43.0",
		)
		svc := newServiceForFalcoVersionTest(t, ds)

		applied, err := svc.UpdateFalcoVersion(context.Background(), newVersion)
		if err != nil {
			t.Fatalf("UpdateFalcoVersion() error = %v", err)
		}
		if applied {
			t.Fatal("UpdateFalcoVersion() applied = true, want false")
		}

		got, err := svc.kubernetesClientSet.AppsV1().DaemonSets(testNamespace).Get(context.Background(), testDSName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get daemonset: %v", err)
		}
		if got.Spec.Template.Spec.Containers[0].Image != "falcosecurity/falco@sha256:0123456789abcdef" {
			t.Errorf("main container image = %q, want unchanged digest-pinned image", got.Spec.Template.Spec.Containers[0].Image)
		}
		if svc.GetFalcoVersion() != "0.43.0" {
			t.Errorf("agent state falco version = %q, want unchanged %q", svc.GetFalcoVersion(), "0.43.0")
		}
	})
}
