package arc

import (
	"context"

	swv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var RunnerGVK = schema.GroupVersionKind{Group: "actions.summerwind.dev", Version: "v1alpha1", Kind: "Runner"}

// RunnerController reconciles legacy GitHub ARC (summerwind) Runner objects.
type RunnerController struct{ Controller }

func (r *RunnerController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj swv1alpha1.Runner
	return r.reconcileObject(ctx, req, RunnerGVK, &obj)
}

func (r *RunnerController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+RunnerGVK.String()+"_"+uuid.NewString()).
		For(&swv1alpha1.Runner{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
