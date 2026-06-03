package argoproj

import (
	"context"

	rolloutv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"aikidoSec.kubernetesAgent/internal/predicates"
)

var RolloutGVK = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Rollout"}

// RolloutController reconciles Argo Rollouts Rollout objects.
type RolloutController struct{ Controller }

func (r *RolloutController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj rolloutv1alpha1.Rollout
	return r.reconcileObject(ctx, req, RolloutGVK, &obj)
}

func (r *RolloutController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RolloutGVK.String()+"_"+uuid.NewString()).
		For(&rolloutv1alpha1.Rollout{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
