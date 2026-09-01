package format

import (
	"aikidoSec.kubernetesAgent/pkg/models"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func FormatObject(obj client.Object, gvk string, state *models.AgentState) client.Object {
	switch gvk {
	case "/v1, Kind=Pod":
		return FormatPod(obj, state)
	case "route.openshift.io/v1, Kind=Route":
		return FormatRoute(obj)
	case "actions.summerwind.dev/v1alpha1, Kind=Runner":
		return FormatRunner(obj)
	}
	return obj
}
