package argoproj

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultRequeueAfter = 12 * time.Hour

// Controller holds the shared state and logic for all argoproj controllers.
type Controller struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func NewController(c client.Client, l *logger.Service, output *batchclient.BatchClient, nsFilter *predicates.NamespaceFilter) Controller {
	return Controller{
		Client:          c,
		Logger:          l,
		OutputClient:    output,
		NamespaceFilter: nsFilter,
	}
}

// reconcileObject is the shared reconcile implementation. Each typed controller
// allocates a zero-value concrete object and delegates here, keeping per-type
// Reconcile methods to a single line.
func (b *Controller) reconcileObject(ctx context.Context, req ctrl.Request, gvk schema.GroupVersionKind, obj client.Object) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	obj.GetObjectKind().SetGroupVersionKind(gvk)
	obj.SetName(req.Name)
	obj.SetNamespace(req.Namespace)

	objectID := gvk.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := b.Get(ctx, req.NamespacedName, obj); {
	case k8serrors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		b.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("could not get %s %v: %w", gvk.Kind, req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	metadata, err := json.Marshal(obj)
	if err != nil {
		b.Logger.ReportError(ctx, err, "error marshalling object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("error marshalling %s: %w", gvk.Kind, err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := b.OutputClient.SendContext(ctx, payload); err != nil {
		b.Logger.ReportError(ctx, err, "error sending payload", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("could not send %s payload: %w", gvk.Kind, err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}
