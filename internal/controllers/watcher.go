package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/format"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

// Watcher reconciles a kubernetes resource
type Watcher struct {
	client.Client
	*models.AgentState
	Logger       *logger.Service
	Scheme       *runtime.Scheme
	Watched      models.WatcherSelector
	OutputClient *batchclient.BatchClient

	// Lock and map that ensures that objects are re-queued only once per defaultRequeueAfter period.
	PendingMu sync.Mutex
	Pending   map[string]time.Time
}

// shouldRequeue ensures an object is requeued at most once per defaultRequeueAfter period.
// Returns true if the object should be requeued. It will return true the first time it is called for a given object or
// after the defaultRequeueAfter period has passed since the last requeue for that object.
// Returns false if the object was marked recently (within defaultRequeueAfter window).
// This prevents duplicate requeues while allowing periodic processing every 12 hours.
func (r *Watcher) shouldRequeue(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	lastRequeue, exists := r.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}

	r.Pending[key] = time.Now()
	return true
}

func (r *Watcher) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
}

func (r *Watcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add a small delay before processing the event to wait for the cache sync since it lags behind by definition.
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()
	requeueAfter := time.Duration(0)

	obj, err := r.GetTypedObject()
	if err != nil {
		r.Logger.ReportError(ctx, err, "error getting typed object for watcher", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, nil
	}
	obj.GetObjectKind().SetGroupVersionKind(r.Watched.GroupVersionKind)
	obj.SetName(req.Name)
	obj.SetNamespace(req.Namespace)

	objectID := r.Watched.String() + "/" + req.String()

	// set event type
	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, obj); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		// Only requeue once per object per defaultRequeueAfter period.
		if r.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
	}

	if eventType == models.ModifiedEventType {
		obj = format.FormatObject(obj, r.Watched.String(), r.AgentState)
	}

	metadata, err := json.Marshal(obj)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling object to JSON", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, fmt.Errorf("error marshalling object to JSON: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending payload to output client", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, fmt.Errorf("could not send payload to output client: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Watcher) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(r.Watched.GroupVersionKind)

	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+r.Watched.GroupVersionKind.String()+"_"+uuid.NewString()).
		For(obj, builder.WithPredicates(predicates.GetPredicatesForGVK(obj.GroupVersionKind().String(), r.Watched.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

func (r *Watcher) GetTypedObject() (client.Object, error) {
	obj, err := r.Scheme.New(r.Watched.GroupVersionKind)
	return obj.(client.Object), err
}
