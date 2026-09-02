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

var EphemeralRunnerGVK = schema.GroupVersionKind{Group: "actions.github.com", Version: "v1alpha1", Kind: "EphemeralRunner"}

// EphemeralRunnerController reconciles GitHub ARC EphemeralRunner objects.
type EphemeralRunnerController struct{ Controller }

func (r *EphemeralRunnerController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj ghv1alpha1.EphemeralRunner
	return r.reconcileObject(ctx, req, EphemeralRunnerGVK, &obj)
}

func (r *EphemeralRunnerController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+EphemeralRunnerGVK.String()+"_"+uuid.NewString()).
		For(&ghv1alpha1.EphemeralRunner{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
