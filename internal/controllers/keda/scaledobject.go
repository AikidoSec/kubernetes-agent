package keda

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	kedav1alpha1 "aikidoSec.kubernetesAgent/pkg/thirdparty/keda/v1alpha1"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

var ScaledObjectGVK = schema.GroupVersionKind{
	Group:   "keda.sh",
	Version: "v1alpha1",
	Kind:    "ScaledObject",
}

// ScaledObjectController reconciles a KEDA ScaledObject.
type ScaledObjectController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter

	PendingMu sync.Mutex
	Pending   map[string]time.Time
}

func (r *ScaledObjectController) shouldRequeue(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	lastRequeue, exists := r.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}

	r.Pending[key] = time.Now()
	return true
}

func (r *ScaledObjectController) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
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
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting ScaledObject", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get ScaledObject %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		if r.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
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
