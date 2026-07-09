package actionsrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

const defaultRequeueAfter = 12 * time.Hour

// Controller holds the shared state and logic for all actions.summerwind.net controllers.
type Controller struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
	PendingMu       sync.Mutex
	Pending         map[string]time.Time
}

func NewController(c client.Client, l *logger.Service, output *batchclient.BatchClient, nsFilter *predicates.NamespaceFilter) Controller {
	return Controller{
		Client:          c,
		Logger:          l,
		OutputClient:    output,
		NamespaceFilter: nsFilter,
		Pending:         make(map[string]time.Time),
	}
}

func (b *Controller) shouldRequeue(key string) bool {
	b.PendingMu.Lock()
	defer b.PendingMu.Unlock()

	lastRequeue, exists := b.Pending[key]
	if exists && time.Since(lastRequeue) < defaultRequeueAfter {
		return false
	}
	b.Pending[key] = time.Now()
	return true
}

func (b *Controller) clearPending(key string) {
	b.PendingMu.Lock()
	delete(b.Pending, key)
	b.PendingMu.Unlock()
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
		b.clearPending(objectID)
	case err != nil:
		b.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace, "asset_type", gvk.String())
		return ctrl.Result{}, fmt.Errorf("could not get %s %v: %w", gvk.Kind, req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		if b.shouldRequeue(objectID) {
			requeueAfter = defaultRequeueAfter
		}
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

// RunnerController reconciles Runner objects.
type RunnerController struct{ Controller }

func (r *RunnerController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj Runner
	return r.reconcileObject(ctx, req, RunnerGVK, &obj)
}

func (r *RunnerController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RunnerGVK.String()+"_"+uuid.NewString()).
		For(&Runner{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// RunnerDeploymentController reconciles RunnerDeployment objects.
type RunnerDeploymentController struct{ Controller }

func (r *RunnerDeploymentController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj RunnerDeployment
	return r.reconcileObject(ctx, req, RunnerDeploymentGVK, &obj)
}

func (r *RunnerDeploymentController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RunnerDeploymentGVK.String()+"_"+uuid.NewString()).
		For(&RunnerDeployment{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// RunnerReplicaSetController reconciles RunnerReplicaSet objects.
type RunnerReplicaSetController struct{ Controller }

func (r *RunnerReplicaSetController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj RunnerReplicaSet
	return r.reconcileObject(ctx, req, RunnerReplicaSetGVK, &obj)
}

func (r *RunnerReplicaSetController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RunnerReplicaSetGVK.String()+"_"+uuid.NewString()).
		For(&RunnerReplicaSet{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// RunnerSetController reconciles RunnerSet objects.
type RunnerSetController struct{ Controller }

func (r *RunnerSetController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj RunnerSet
	return r.reconcileObject(ctx, req, RunnerSetGVK, &obj)
}

func (r *RunnerSetController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RunnerSetGVK.String()+"_"+uuid.NewString()).
		For(&RunnerSet{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
