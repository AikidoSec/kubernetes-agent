package v1alpha1_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/keda/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/apis/stubtest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStubs(t *testing.T) {
	for _, kind := range []stubtest.Kind{
		{
			GVK:     v1alpha1.GroupVersion.WithKind("ScaledObject"),
			Object:  func() client.Object { return &v1alpha1.ScaledObject{} },
			List:    func() client.ObjectList { return &v1alpha1.ScaledObjectList{} },
			Install: v1alpha1.AddToScheme,
		},
		{
			GVK:     v1alpha1.GroupVersion.WithKind("ScaledJob"),
			Object:  func() client.Object { return &v1alpha1.ScaledJob{} },
			List:    func() client.ObjectList { return &v1alpha1.ScaledJobList{} },
			Install: v1alpha1.AddToScheme,
		},
	} {
		t.Run(kind.GVK.Kind, func(t *testing.T) { stubtest.Run(t, kind) })
	}
}
