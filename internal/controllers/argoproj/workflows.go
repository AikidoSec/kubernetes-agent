package argoproj

import (
	"context"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"aikidoSec.kubernetesAgent/internal/predicates"
)

var (
	WorkflowGVK                = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Workflow"}
	WorkflowTemplateGVK        = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "WorkflowTemplate"}
	CronWorkflowGVK            = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "CronWorkflow"}
	ClusterWorkflowTemplateGVK = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "ClusterWorkflowTemplate"}
)

// WorkflowController reconciles Argo Workflows Workflow objects.
type WorkflowController struct{ Controller }

func (r *WorkflowController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj wfv1alpha1.Workflow
	return r.reconcileObject(ctx, req, WorkflowGVK, &obj)
}

func (r *WorkflowController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+WorkflowGVK.String()+"_"+uuid.NewString()).
		For(&wfv1alpha1.Workflow{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// WorkflowTemplateController reconciles Argo Workflows WorkflowTemplate objects.
type WorkflowTemplateController struct{ Controller }

func (r *WorkflowTemplateController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj wfv1alpha1.WorkflowTemplate
	return r.reconcileObject(ctx, req, WorkflowTemplateGVK, &obj)
}

func (r *WorkflowTemplateController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+WorkflowTemplateGVK.String()+"_"+uuid.NewString()).
		For(&wfv1alpha1.WorkflowTemplate{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// CronWorkflowController reconciles Argo Workflows CronWorkflow objects.
type CronWorkflowController struct{ Controller }

func (r *CronWorkflowController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj wfv1alpha1.CronWorkflow
	return r.reconcileObject(ctx, req, CronWorkflowGVK, &obj)
}

func (r *CronWorkflowController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+CronWorkflowGVK.String()+"_"+uuid.NewString()).
		For(&wfv1alpha1.CronWorkflow{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}

// ClusterWorkflowTemplateController reconciles Argo Workflows ClusterWorkflowTemplate objects.
// ClusterWorkflowTemplate is cluster-scoped; namespace filtering is a no-op for empty namespaces.
type ClusterWorkflowTemplateController struct{ Controller }

func (r *ClusterWorkflowTemplateController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj wfv1alpha1.ClusterWorkflowTemplate
	return r.reconcileObject(ctx, req, ClusterWorkflowTemplateGVK, &obj)
}

func (r *ClusterWorkflowTemplateController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+ClusterWorkflowTemplateGVK.String()+"_"+uuid.NewString()).
		For(&wfv1alpha1.ClusterWorkflowTemplate{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
