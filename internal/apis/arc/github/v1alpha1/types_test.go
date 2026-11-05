package v1alpha1_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/apis/stubtest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStubs(t *testing.T) {
	for _, kind := range []stubtest.Kind{
		{
			GVK:     v1alpha1.SchemeGroupVersion.WithKind("EphemeralRunner"),
			Object:  func() client.Object { return &v1alpha1.EphemeralRunner{} },
			List:    func() client.ObjectList { return &v1alpha1.EphemeralRunnerList{} },
			Install: v1alpha1.AddToScheme,
		},
		{
			GVK:     v1alpha1.SchemeGroupVersion.WithKind("AutoscalingListener"),
			Object:  func() client.Object { return &v1alpha1.AutoscalingListener{} },
			List:    func() client.ObjectList { return &v1alpha1.AutoscalingListenerList{} },
			Install: v1alpha1.AddToScheme,
		},
	} {
		t.Run(kind.GVK.Kind, func(t *testing.T) { stubtest.Run(t, kind) })
	}
}
