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

var TriggerAuthenticationGVK = schema.GroupVersionKind{
	Group:   "keda.sh",
	Version: "v1alpha1",
	Kind:    "TriggerAuthentication",
}

var ClusterTriggerAuthenticationGVK = schema.GroupVersionKind{
	Group:   "keda.sh",
	Version: "v1alpha1",
	Kind:    "ClusterTriggerAuthentication",
}

// TriggerAuthenticationController reconciles a KEDA TriggerAuthentication.
type TriggerAuthenticationController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter

	PendingMu sync.Mutex
	Pending   map[string]time.Time
}

func (r *TriggerAuthenticationController) shouldRequeue(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	lastRequeue, exists := r.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}

	r.Pending[key] = time.Now()
	return true
}

func (r *TriggerAuthenticationController) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
}

func (r *TriggerAuthenticationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var ta kedav1alpha1.TriggerAuthentication
	ta.GetObjectKind().SetGroupVersionKind(TriggerAuthenticationGVK)
	ta.SetName(req.Name)
	ta.SetNamespace(req.Namespace)

	objectID := TriggerAuthenticationGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &ta); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting TriggerAuthentication", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get TriggerAuthentication %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		if r.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
	}

	metadata, err := json.Marshal(ta)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling TriggerAuthentication", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling TriggerAuthentication: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending TriggerAuthentication payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send TriggerAuthentication payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *TriggerAuthenticationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+TriggerAuthenticationGVK.String()+"_"+uuid.NewString()).
		For(&kedav1alpha1.TriggerAuthentication{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// ClusterTriggerAuthenticationController reconciles a KEDA ClusterTriggerAuthentication.
type ClusterTriggerAuthenticationController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter

	PendingMu sync.Mutex
	Pending   map[string]time.Time
}

func (r *ClusterTriggerAuthenticationController) shouldRequeue(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	lastRequeue, exists := r.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}

	r.Pending[key] = time.Now()
	return true
}

func (r *ClusterTriggerAuthenticationController) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
}

func (r *ClusterTriggerAuthenticationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var cta kedav1alpha1.ClusterTriggerAuthentication
	cta.GetObjectKind().SetGroupVersionKind(ClusterTriggerAuthenticationGVK)
	cta.SetName(req.Name)

	objectID := ClusterTriggerAuthenticationGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &cta); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting ClusterTriggerAuthentication", "watcherError", "name", req.Name)
		return ctrl.Result{}, fmt.Errorf("could not get ClusterTriggerAuthentication %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		if r.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
	}

	metadata, err := json.Marshal(cta)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling ClusterTriggerAuthentication", "watcherError", "name", req.Name)
		return ctrl.Result{}, fmt.Errorf("error marshalling ClusterTriggerAuthentication: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending ClusterTriggerAuthentication payload", "watcherError", "name", req.Name)
		return ctrl.Result{}, fmt.Errorf("could not send ClusterTriggerAuthentication payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *ClusterTriggerAuthenticationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+ClusterTriggerAuthenticationGVK.String()+"_"+uuid.NewString()).
		For(&kedav1alpha1.ClusterTriggerAuthentication{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
