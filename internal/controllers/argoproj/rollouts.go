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

var (
	RolloutGVK                 = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Rollout"}
	AnalysisTemplateGVK        = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "AnalysisTemplate"}
	ClusterAnalysisTemplateGVK = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "ClusterAnalysisTemplate"}
	AnalysisRunGVK             = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "AnalysisRun"}
)

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

// AnalysisTemplateController reconciles Argo Rollouts AnalysisTemplate objects.
type AnalysisTemplateController struct{ Controller }

func (r *AnalysisTemplateController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj rolloutv1alpha1.AnalysisTemplate
	return r.reconcileObject(ctx, req, AnalysisTemplateGVK, &obj)
}

func (r *AnalysisTemplateController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+AnalysisTemplateGVK.String()+"_"+uuid.NewString()).
		For(&rolloutv1alpha1.AnalysisTemplate{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// ClusterAnalysisTemplateController reconciles Argo Rollouts ClusterAnalysisTemplate objects.
// ClusterAnalysisTemplate is cluster-scoped; namespace filtering is a no-op for empty namespaces.
type ClusterAnalysisTemplateController struct{ Controller }

func (r *ClusterAnalysisTemplateController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj rolloutv1alpha1.ClusterAnalysisTemplate
	return r.reconcileObject(ctx, req, ClusterAnalysisTemplateGVK, &obj)
}

func (r *ClusterAnalysisTemplateController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+ClusterAnalysisTemplateGVK.String()+"_"+uuid.NewString()).
		For(&rolloutv1alpha1.ClusterAnalysisTemplate{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// AnalysisRunController reconciles Argo Rollouts AnalysisRun objects.
type AnalysisRunController struct{ Controller }

func (r *AnalysisRunController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj rolloutv1alpha1.AnalysisRun
	return r.reconcileObject(ctx, req, AnalysisRunGVK, &obj)
}

func (r *AnalysisRunController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+AnalysisRunGVK.String()+"_"+uuid.NewString()).
		For(&rolloutv1alpha1.AnalysisRun{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
