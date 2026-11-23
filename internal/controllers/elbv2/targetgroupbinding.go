package elbv2

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	elbv2v1beta1 "aikidoSec.kubernetesAgent/internal/apis/elbv2/v1beta1"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

var TargetGroupBindingGVK = elbv2v1beta1.GroupVersion.WithKind("TargetGroupBinding")

type TargetGroupBindingController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func (r *TargetGroupBindingController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	eventTime := time.Now().UTC()
	var obj elbv2v1beta1.TargetGroupBinding
	obj.SetName(req.Name)
	obj.SetNamespace(req.Namespace)

	var eventType models.EventType
	var requeueAfter time.Duration
	switch err := r.Get(ctx, req.NamespacedName, &obj); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting TargetGroupBinding", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get TargetGroupBinding %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	obj.SetGroupVersionKind(TargetGroupBindingGVK)
	metadata, err := json.Marshal(&obj)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling TargetGroupBinding", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling TargetGroupBinding: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: TargetGroupBindingGVK.String() + "/" + req.String(),
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending TargetGroupBinding payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send TargetGroupBinding payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *TargetGroupBindingController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+TargetGroupBindingGVK.String()+"_"+uuid.NewString()).
		For(&elbv2v1beta1.TargetGroupBinding{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
