package v1alpha1_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/kong/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/apis/stubtest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStubs(t *testing.T) {
	for _, kind := range []stubtest.Kind{
		{
			GVK:     v1alpha1.GroupVersion.WithKind("KongRoute"),
			Object:  func() client.Object { return &v1alpha1.KongRoute{} },
			List:    func() client.ObjectList { return &v1alpha1.KongRouteList{} },
			Install: v1alpha1.AddToScheme,
		},
		{
			GVK:     v1alpha1.GroupVersion.WithKind("KongService"),
			Object:  func() client.Object { return &v1alpha1.KongService{} },
			List:    func() client.ObjectList { return &v1alpha1.KongServiceList{} },
			Install: v1alpha1.AddToScheme,
		},
	} {
		t.Run(kind.GVK.Kind, func(t *testing.T) { stubtest.Run(t, kind) })
	}
}
