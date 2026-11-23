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

var VirtualServiceGVK = istiov1.GroupVersion.WithKind("VirtualService")

type VirtualServiceController struct{ Controller }

func (r *VirtualServiceController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.reconcileObject(ctx, req, VirtualServiceGVK, &istiov1.VirtualService{})
}

func (r *VirtualServiceController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+VirtualServiceGVK.String()+"_"+uuid.NewString()).
		For(&istiov1.VirtualService{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
