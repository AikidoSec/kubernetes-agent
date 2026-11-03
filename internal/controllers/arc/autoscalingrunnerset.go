package arc

import (
	"context"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var AutoscalingRunnerSetGVK = schema.GroupVersionKind{Group: "actions.github.com", Version: "v1alpha1", Kind: "AutoscalingRunnerSet"}

// AutoscalingRunnerSetController reconciles GitHub ARC AutoscalingRunnerSet objects.
type AutoscalingRunnerSetController struct{ Controller }

func (r *AutoscalingRunnerSetController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj ghv1alpha1.AutoscalingRunnerSet
	return r.reconcileObject(ctx, req, AutoscalingRunnerSetGVK, &obj)
}

func (r *AutoscalingRunnerSetController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+AutoscalingRunnerSetGVK.String()+"_"+uuid.NewString()).
		For(&ghv1alpha1.AutoscalingRunnerSet{}, builder.WithPredicates(predicates.GetPredicatesForGVK(AutoscalingRunnerSetGVK.String(), r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
