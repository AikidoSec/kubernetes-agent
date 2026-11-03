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

var EphemeralRunnerSetGVK = schema.GroupVersionKind{Group: "actions.github.com", Version: "v1alpha1", Kind: "EphemeralRunnerSet"}

// EphemeralRunnerSetController reconciles GitHub ARC EphemeralRunnerSet objects.
type EphemeralRunnerSetController struct{ Controller }

func (r *EphemeralRunnerSetController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj ghv1alpha1.EphemeralRunnerSet
	return r.reconcileObject(ctx, req, EphemeralRunnerSetGVK, &obj)
}

func (r *EphemeralRunnerSetController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+EphemeralRunnerSetGVK.String()+"_"+uuid.NewString()).
		For(&ghv1alpha1.EphemeralRunnerSet{}, builder.WithPredicates(predicates.GetPredicatesForGVK(EphemeralRunnerSetGVK.String(), r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
