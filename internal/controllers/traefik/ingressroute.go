package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	traefikv1alpha1 "github.com/traefik/traefik/v3/pkg/provider/kubernetes/crd/traefikio/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var IngressRouteGVK = schema.GroupVersionKind{
	Group:   traefikv1alpha1.GroupName,
	Version: "v1alpha1",
	Kind:    "IngressRoute",
}

const defaultRequeueAfter = 12 * time.Hour

// IngressRouteController reconciles a Traefik IngressRoute object.
type IngressRouteController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func (r *IngressRouteController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add a small delay before processing the event to wait for the cache sync since it lags behind by definition.
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var ingressRoute traefikv1alpha1.IngressRoute
	ingressRoute.GetObjectKind().SetGroupVersionKind(IngressRouteGVK)
	ingressRoute.SetName(req.Name)
	ingressRoute.SetNamespace(req.Namespace)

	objectID := IngressRouteGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &ingressRoute); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting IngressRoute", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get IngressRoute %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	metadata, err := json.Marshal(ingressRoute)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling IngressRoute", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling IngressRoute: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending IngressRoute payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send IngressRoute payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressRouteController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+IngressRouteGVK.String()+"_"+uuid.NewString()).
		For(&traefikv1alpha1.IngressRoute{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
