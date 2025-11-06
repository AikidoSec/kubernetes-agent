package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

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
	Logger       *logger.Service
	Scheme       *runtime.Scheme
	Watched      models.WatcherSelector
	OutputClient *batchclient.BatchClient

	// Lock and map that ensures that objects are re-queued only once
	PendingMu sync.Mutex
	Pending   map[string]struct{}
}

func (r *Watcher) markPendingOnce(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	if _, ok := r.Pending[key]; ok {
		return false
	}

	r.Pending[key] = struct{}{}
	return true
}

func (r *Watcher) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
}

func (r *Watcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	eventTime := time.Now().UTC()
	requeueAfter := defaultRequeueAfter

	obj, err := r.GetTypedObject()
	if err != nil {
		r.Logger.ReportError(ctx, err, "error getting typed object for watcher", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, nil
	}
	objectID := r.Watched.String() + "/" + req.String()

	// set event type
	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, obj); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
		requeueAfter = 0 // no need to requeue deleted objects
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
	}

	obj, err = r.SetObjectGVK(obj)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error ensuring GVK for object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", r.Watched.String())
		return ctrl.Result{}, fmt.Errorf("error ensuring GVK for object: %w", err)
	}

	// If the object is already pending for processing, skip re-queuing it
	if v := r.markPendingOnce(objectID); !v {
		requeueAfter = 0
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
		For(obj, builder.WithPredicates(predicates.GetPredicatesForGVK(obj.GroupVersionKind().String(), r.Watched.ExcludedNamespaces))).
		WithOptions(opts).
		Complete(r)
}

func (r *Watcher) GetTypedObject() (client.Object, error) {
	obj, err := r.Scheme.New(r.Watched.GroupVersionKind)
	return obj.(client.Object), err
}

func (r *Watcher) SetObjectGVK(obj client.Object) (client.Object, error) {
	gvk, err := apiutil.GVKForObject(obj, r.Client.Scheme())
	if err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}
