package keda

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
)

var ScaledObjectGVK = schema.GroupVersionKind{
	Group:   "keda.sh",
	Version: "v1alpha1",
	Kind:    "ScaledObject",
}

// ScaledObjectController reconciles KEDA ScaledObject objects.
type ScaledObjectController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func (r *ScaledObjectController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var scaledObject kedav1alpha1.ScaledObject
	scaledObject.GetObjectKind().SetGroupVersionKind(ScaledObjectGVK)
	scaledObject.SetName(req.Name)
	scaledObject.SetNamespace(req.Namespace)

	objectID := ScaledObjectGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &scaledObject); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting ScaledObject", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get ScaledObject %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	metadata, err := json.Marshal(scaledObject)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling ScaledObject", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling ScaledObject: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending ScaledObject payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send ScaledObject payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *ScaledObjectController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+ScaledObjectGVK.String()+"_"+uuid.NewString()).
		For(&kedav1alpha1.ScaledObject{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
