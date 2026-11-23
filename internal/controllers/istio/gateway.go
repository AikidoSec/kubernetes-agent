package istio

import (
	"context"

	istiov1 "aikidoSec.kubernetesAgent/internal/apis/istio/v1"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"github.com/google/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var GatewayGVK = istiov1.GroupVersion.WithKind("Gateway")

type GatewayController struct{ Controller }

func (r *GatewayController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.reconcileObject(ctx, req, GatewayGVK, &istiov1.Gateway{})
}

func (r *GatewayController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+GatewayGVK.String()+"_"+uuid.NewString()).
		For(&istiov1.Gateway{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
