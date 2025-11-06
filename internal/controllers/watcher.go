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

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
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
	switch r.Watched.String() {
	case "/v1, Kind=Pod":
		return &corev1.Pod{}, nil
	case "/v1, Kind=Endpoints":
		return &corev1.Endpoints{}, nil
	case "/v1, Kind=Service":
		return &corev1.Service{}, nil
	case "/v1, Kind=Namespace":
		return &corev1.Namespace{}, nil
	case "/v1, Kind=Node":
		return &corev1.Node{}, nil
	case "/v1, Kind=ServiceAccount":
		return &corev1.ServiceAccount{}, nil
	case "/v1, Kind=ConfigMap":
		return &corev1.ConfigMap{}, nil
	case "/v1, Kind=PersistentVolume":
		return &corev1.PersistentVolume{}, nil
	case "/v1, Kind=PersistentVolumeClaim":
		return &corev1.PersistentVolumeClaim{}, nil
	case "apps/v1, Kind=Deployment":
		return &appsv1.Deployment{}, nil
	case "apps/v1, Kind=DaemonSet":
		return &appsv1.DaemonSet{}, nil
	case "apps/v1, Kind=StatefulSet":
		return &appsv1.StatefulSet{}, nil
	case "apps/v1, Kind=ReplicaSet":
		return &appsv1.ReplicaSet{}, nil
	case "rbac.authorization.k8s.io/v1, Kind=Role":
		return &rbacv1.Role{}, nil
	case "rbac.authorization.k8s.io/v1, Kind=RoleBinding":
		return &rbacv1.RoleBinding{}, nil
	case "rbac.authorization.k8s.io/v1, Kind=ClusterRole":
		return &rbacv1.ClusterRole{}, nil
	case "rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding":
		return &rbacv1.ClusterRoleBinding{}, nil
	case "networking.k8s.io/v1, Kind=NetworkPolicy":
		return &networkingv1.NetworkPolicy{}, nil
	case "networking.k8s.io/v1, Kind=Ingress":
		return &networkingv1.Ingress{}, nil
	case "batch/v1, Kind=Job":
		return &batchv1.Job{}, nil
	case "batch/v1, Kind=CronJob":
		return &batchv1.CronJob{}, nil
	case "storage.k8s.io/v1, Kind=StorageClass":
		return &storagev1.StorageClass{}, nil
	case "discovery.k8s.io/v1, Kind=EndpointSlice":
		return &discoveryv1.EndpointSlice{}, nil
	default:
		return nil, fmt.Errorf("could not determine type for GVK %v", r.Watched.String())
	}
}
