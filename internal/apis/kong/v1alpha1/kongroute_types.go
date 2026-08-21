package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KongRoute is the schema for Routes API which defines a Kong Route.
type KongRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KongRouteSpec `json:"spec"`

	// +kubebuilder:default={conditions: {{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status KongRouteStatus `json:"status,omitempty"`
}

// KongRouteSpec defines spec of a Kong Route.
type KongRouteSpec struct {
	// ControlPlaneRef is a reference to a ControlPlane this KongRoute is associated with.
	// Route can either specify a ControlPlaneRef and be 'serviceless' route or
	// specify a ServiceRef and be associated with a Service.
	// +optional
	ControlPlaneRef *ControlPlaneRef `json:"controlPlaneRef,omitempty"`
	// ServiceRef is a reference to a Service this KongRoute is associated with.
	// Route can either specify a ControlPlaneRef and be 'serviceless' route or
	// specify a ServiceRef and be associated with a Service.
	// +optional
	ServiceRef *ServiceRef `json:"serviceRef,omitempty"`

	KongRouteAPISpec `json:",inline"`
}

// KongRouteAPISpec represents the configuration of a Route in Kong as defined by the Konnect API.
//
// These fields are mostly copied from sdk-konnect-go but some modifications have been made
// to make the code generation required for Kubernetes CRDs work.
type KongRouteAPISpec struct {
	// A list of IP destinations of incoming connections that match this Route when using stream routing. Each entry is an object with fields "ip" (optionally in CIDR range notation) and/or "port".
	Destinations []Destinations `json:"destinations,omitempty"`
	// One or more lists of values indexed by header name that will cause this Route to match if present in the request. The `Host` header cannot be used with this attribute: hosts should be specified using the `hosts` attribute. When `headers` contains only one value and that value starts with the special prefix `~*`, the value is interpreted as a regular expression.
	Headers map[string][]string `json:"headers,omitempty"`
	// A list of domain names that match this Route. Note that the hosts value is case sensitive.
	Hosts []string `json:"hosts,omitempty"`
	// The status code Kong responds with when all properties of a Route match except the protocol i.e. if the protocol of the request is `HTTP` instead of `HTTPS`. `Location` header is injected by Kong if the field is set to 301, 302, 307 or 308. Note: This config applies only if the Route is configured to only accept the `https` protocol.
	HTTPSRedirectStatusCode *HTTPSRedirectStatusCode `json:"https_redirect_status_code,omitempty"`
	// A list of HTTP methods that match this Route.
	Methods []string `json:"methods,omitempty"`
	// The name of the Route. Route names must be unique, and they are case sensitive. For example, there can be two different Routes named "test" and "Test".
	Name *string `json:"name,omitempty"`
	// Controls how the Service path, Route path and requested path are combined when sending a request to the upstream. See above for a detailed description of each behavior.
	PathHandling *PathHandling `json:"path_handling,omitempty"`
	// A list of paths that match this Route.
	Paths []string `json:"paths,omitempty"`
	// When matching a Route via one of the `hosts` domain names, use the request `Host` header in the upstream request headers. If set to `false`, the upstream `Host` header will be that of the Service's `host`.
	PreserveHost *bool `json:"preserve_host,omitempty"`
	// An array of the protocols this Route should allow. See KongRoute for a list of accepted protocols. When set to only `"https"`, HTTP requests are answered with an upgrade error. When set to only `"http"`, HTTPS requests are answered with an error.
	Protocols []RouteJSONProtocols `json:"protocols,omitempty"`
	// A number used to choose which route resolves a given request when several routes match it using regexes simultaneously. When two routes match the path and have the same `regex_priority`, the older one (lowest `created_at`) is used. Note that the priority for non-regex routes is different (longer non-regex routes are matched before shorter ones).
	RegexPriority *int64 `json:"regex_priority,omitempty"`
	// Whether to enable request body buffering or not. With HTTP 1.1, it may make sense to turn this off on services that receive data with chunked transfer encoding.
	RequestBuffering *bool `json:"request_buffering,omitempty"`
	// Whether to enable response body buffering or not. With HTTP 1.1, it may make sense to turn this off on services that send data with chunked transfer encoding.
	ResponseBuffering *bool `json:"response_buffering,omitempty"`
	// A list of SNIs that match this Route when using stream routing.
	Snis []string `json:"snis,omitempty"`
	// A list of IP sources of incoming connections that match this Route when using stream routing. Each entry is an object with fields "ip" (optionally in CIDR range notation) and/or "port".
	Sources []Sources `json:"sources,omitempty"`
	// When matching a Route via one of the `paths`, strip the matching prefix from the upstream request URL.
	StripPath *bool `json:"strip_path,omitempty"`
	// An optional set of strings associated with the Route for grouping and filtering.
	Tags Tags `json:"tags,omitempty"`
}

// KongRouteStatus represents the current status of the Kong Route resource.
type KongRouteStatus struct {
	// Konnect contains the Konnect entity status.
	// +optional
	Konnect *KonnectEntityStatusWithControlPlaneAndServiceRefs `json:"konnect,omitempty"`

	// Conditions describe the status of the Konnect entity.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// KongRouteList contains a list of Kong Routes.
type KongRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KongRoute `json:"items"`
}
