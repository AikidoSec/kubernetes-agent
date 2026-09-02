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

var AutoscalingListenerGVK = schema.GroupVersionKind{Group: "actions.github.com", Version: "v1alpha1", Kind: "AutoscalingListener"}

// AutoscalingListenerController reconciles GitHub ARC AutoscalingListener objects.
type AutoscalingListenerController struct{ Controller }

func (r *AutoscalingListenerController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj ghv1alpha1.AutoscalingListener
	return r.reconcileObject(ctx, req, AutoscalingListenerGVK, &obj)
}

func (r *AutoscalingListenerController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+AutoscalingListenerGVK.String()+"_"+uuid.NewString()).
		For(&ghv1alpha1.AutoscalingListener{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
