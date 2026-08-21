package v1alpha1

// Upstream registers all twenty Traefik CRD kinds; the scheme only needs the ones the
// client touches.

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kschema "k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the group name for Traefik.
const GroupName = "traefik.io"

var (
	// SchemeBuilder collects the scheme builder functions.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme applies the SchemeBuilder functions to a specified scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// SchemeGroupVersion is group version used to register these objects.
var SchemeGroupVersion = kschema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// Adds the list of known types to Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&IngressRoute{},
		&IngressRouteList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
