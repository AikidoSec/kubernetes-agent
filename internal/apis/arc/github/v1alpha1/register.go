package v1alpha1

// The agent watches EphemeralRunner and AutoscalingListener — the only
// actions.github.com kinds that directly own a Pod. The other kinds in this
// group (AutoscalingRunnerSet, EphemeralRunnerSet) are not registered.

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is the group version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: "actions.github.com", Version: "v1alpha1"}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&EphemeralRunner{},
		&EphemeralRunnerList{},
		&AutoscalingListener{},
		&AutoscalingListenerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
