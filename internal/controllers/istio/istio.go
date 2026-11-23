package istio

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultRequeueAfter = 12 * time.Hour

// Controller holds the shared state and reconciliation logic for Istio controllers.
type Controller struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func (r *Controller) reconcileObject(ctx context.Context, req ctrl.Request, gvk schema.GroupVersionKind, obj client.Object) (ctrl.Result, error) {
	eventTime := time.Now().UTC()
	obj.SetName(req.Name)
	obj.SetNamespace(req.Namespace)

	var eventType models.EventType
	var requeueAfter time.Duration
	switch err := r.Get(ctx, req.NamespacedName, obj); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting Istio object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("could not get Istio %s %v: %w", gvk.Kind, req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	obj.GetObjectKind().SetGroupVersionKind(gvk)
	metadata, err := json.Marshal(obj)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling Istio object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("error marshalling Istio %s: %w", gvk.Kind, err)
	}

	payload := models.AssetPayload{
		ObjectUID: gvk.String() + "/" + req.String(),
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending Istio payload", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("could not send Istio %s payload: %w", gvk.Kind, err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}
