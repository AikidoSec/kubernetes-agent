package kong

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
	kongv1alpha1 "github.com/kong/kubernetes-configuration/v2/api/configuration/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

var KongServiceGVK = schema.GroupVersionKind{
	Group:   "configuration.konghq.com",
	Version: "v1alpha1",
	Kind:    "KongService",
}

// KongServiceController reconciles a Kong KongService object.
type KongServiceController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter

	PendingMu sync.Mutex
	Pending   map[string]time.Time
}

func (r *KongServiceController) shouldRequeue(key string) bool {
	r.PendingMu.Lock()
	defer r.PendingMu.Unlock()

	lastRequeue, exists := r.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}

	r.Pending[key] = time.Now()
	return true
}

func (r *KongServiceController) clearPending(key string) {
	r.PendingMu.Lock()
	delete(r.Pending, key)
	r.PendingMu.Unlock()
}

func (r *KongServiceController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add a small delay before processing the event to wait for the cache sync since it lags behind by definition.
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var kongService kongv1alpha1.KongService
	kongService.GetObjectKind().SetGroupVersionKind(KongServiceGVK)
	kongService.SetName(req.Name)
	kongService.SetNamespace(req.Namespace)

	objectID := KongServiceGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &kongService); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
		r.clearPending(objectID)
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting KongService", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get KongService %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		if r.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
	}

	metadata, err := json.Marshal(kongService)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling KongService", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling KongService: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending KongService payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send KongService payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KongServiceController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+KongServiceGVK.String()+"_"+uuid.NewString()).
		For(&kongv1alpha1.KongService{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
