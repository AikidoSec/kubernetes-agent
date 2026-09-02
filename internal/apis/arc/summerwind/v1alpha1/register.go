package v1alpha1

// The agent watches Runner — the only legacy (summerwind) ARC kind that directly
// owns a Pod. RunnerReplicaSet/RunnerDeployment/RunnerSet/HorizontalRunnerAutoscaler
// are not registered.
//
// NOTE: the group constant is actions.summerwind.dev, though the upstream source
// directory is named actions.summerwind.net.

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is the group version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: "actions.summerwind.dev", Version: "v1alpha1"}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Runner{},
		&RunnerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
