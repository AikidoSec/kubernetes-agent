package format

import (
	routev1 "github.com/openshift/api/route/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FormatRoute drops the certificate material an OpenShift Route embeds in its spec.
// An Ingress keeps that material in a Secret, which the agent never collects, so
// stripping it keeps Routes at the same exposure and leaves the termination mode,
// which is all that is needed to reason about the route.
func FormatRoute(obj client.Object) client.Object {
	route, ok := obj.(*routev1.Route)
	if !ok {
		return obj
	}

	if route.Spec.TLS == nil {
		return route
	}

	route.Spec.TLS.Certificate = ""
	route.Spec.TLS.Key = ""
	route.Spec.TLS.CACertificate = ""
	route.Spec.TLS.DestinationCACertificate = ""

	return route
}
