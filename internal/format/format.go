package format

import (
	"aikidoSec.kubernetesAgent/pkg/models"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func FormatObject(obj client.Object, gvk string, state *models.AgentState) client.Object {
	switch gvk {
	case "/v1, Kind=Pod":
		return FormatPod(obj, state)
	}
	return obj
}
