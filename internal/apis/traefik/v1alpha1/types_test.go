package v1alpha1_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/apis/stubtest"
	"aikidoSec.kubernetesAgent/internal/apis/traefik/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStubs(t *testing.T) {
	for _, kind := range []stubtest.Kind{
		{
			GVK:     v1alpha1.SchemeGroupVersion.WithKind("IngressRoute"),
			Object:  func() client.Object { return &v1alpha1.IngressRoute{} },
			List:    func() client.ObjectList { return &v1alpha1.IngressRouteList{} },
			Install: v1alpha1.AddToScheme,
		},
	} {
		t.Run(kind.GVK.Kind, func(t *testing.T) { stubtest.Run(t, kind) })
	}
}
