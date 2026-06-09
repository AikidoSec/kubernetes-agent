package argoproj

import (
	"context"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"aikidoSec.kubernetesAgent/internal/predicates"
)

// Local type stubs for ArgoCD CRDs.
//
// github.com/argoproj/argo-cd/v2 transitively imports k8s.io/kubernetes which
// cannot coexist with our standalone k8s sub-packages. These stubs satisfy the
// controller-runtime scheme registration and client.Object requirements while
// preserving full Spec/Status JSON via runtime.RawExtension.

var (
	ApplicationGVK = schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Application"}

	argoCDSchemeBuilder = runtime.NewSchemeBuilder(addArgoCDKnownTypes)
	AddArgoCDToScheme   = argoCDSchemeBuilder.AddToScheme

	argoCDGroupVersion = schema.GroupVersion{Group: "argoproj.io", Version: "v1alpha1"}
)

func addArgoCDKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(argoCDGroupVersion,
		&Application{},
		&ApplicationList{},
	)
	metav1.AddToGroupVersion(s, argoCDGroupVersion)
	return nil
}

// Application represents an ArgoCD Application.
type Application struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              runtime.RawExtension `json:"spec"`
	Status            runtime.RawExtension `json:"status"`
}

func (a *Application) DeepCopyObject() runtime.Object { return a.DeepCopy() }
func (a *Application) DeepCopy() *Application {
	if a == nil {
		return nil
	}
	out := &Application{TypeMeta: a.TypeMeta}
	a.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if a.Spec.Raw != nil {
		out.Spec.Raw = append([]byte{}, a.Spec.Raw...)
	}
	if a.Status.Raw != nil {
		out.Status.Raw = append([]byte{}, a.Status.Raw...)
	}
	return out
}

func (a *Application) DeepCopyInto(out *Application) { *out = *a.DeepCopy() }

// ApplicationList is a list of Application resources.
type ApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Application `json:"items"`
}

func (l *ApplicationList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &ApplicationList{TypeMeta: l.TypeMeta}
	l.DeepCopyInto(&out.ListMeta)
	out.Items = make([]Application, len(l.Items))
	for i := range l.Items {
		l.Items[i].DeepCopyInto(&out.Items[i])
	}
	return out
}

// ApplicationController reconciles ArgoCD Application objects.
type ApplicationController struct{ Controller }

func (r *ApplicationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj Application
	return r.reconcileObject(ctx, req, ApplicationGVK, &obj)
}

func (r *ApplicationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+ApplicationGVK.String()+"_"+uuid.NewString()).
		For(&Application{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
