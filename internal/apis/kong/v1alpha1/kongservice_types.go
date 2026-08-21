package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KongService is the schema for Services API which defines a Kong Service.
type KongService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KongServiceSpec `json:"spec"`

	// +kubebuilder:default={conditions: {{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status KongServiceStatus `json:"status,omitempty"`
}

// KongServiceSpec defines specification of a Kong Service.
type KongServiceSpec struct {
	// ControlPlaneRef is a reference to a ControlPlane this KongService is associated with.
	// +required
	ControlPlaneRef *ControlPlaneRef `json:"controlPlaneRef"`

	KongServiceAPISpec `json:",inline"`
}

// KongServiceAPISpec defines the specification of a Kong Service.
type KongServiceAPISpec struct {
	// Helper field to set `protocol`, `host`, `port` and `path` using a URL. This field is write-only and is not returned in responses.
	URL *string `json:"url,omitempty"`
	// The timeout in milliseconds for establishing a connection to the upstream server.
	ConnectTimeout *int64 `json:"connect_timeout,omitempty"`
	// Whether the Service is active. If set to `false`, the proxy behavior will be as if any routes attached to it do not exist (404). Default: `true`.
	Enabled *bool `json:"enabled,omitempty"`
	// The host of the upstream server. Note that the host value is case sensitive.
	// +required
	Host string `json:"host"`
	// The Service name.
	Name *string `json:"name,omitempty"`
	// The path to be used in requests to the upstream server.
	Path *string `json:"path,omitempty"`
	// The upstream server port.
	Port int64 `json:"port,omitempty"`
	// The protocol used to communicate with the upstream.
	Protocol Protocol `json:"protocol,omitempty"`
	// The timeout in milliseconds between two successive read operations for transmitting a request to the upstream server.
	ReadTimeout *int64 `json:"read_timeout,omitempty"`
	// The number of retries to execute upon failure to proxy.
	Retries *int64 `json:"retries,omitempty"`
	// An optional set of strings associated with the Service for grouping and filtering.
	Tags Tags `json:"tags,omitempty"`
	// Whether to enable verification of upstream server TLS certificate. If set to `null`, then the Nginx default is respected.
	TLSVerify *bool `json:"tls_verify,omitempty"`
	// Maximum depth of chain while verifying Upstream server's TLS certificate. If set to `null`, then the Nginx default is respected.
	TLSVerifyDepth *int64 `json:"tls_verify_depth,omitempty"`
	// The timeout in milliseconds between two successive write operations for transmitting a request to the upstream server.
	WriteTimeout *int64 `json:"write_timeout,omitempty"`
}

// KongServiceStatus represents the current status of the Kong Service resource.
type KongServiceStatus struct {
	// Konnect contains the Konnect entity status.
	// +optional
	Konnect *KonnectEntityStatusWithControlPlaneRef `json:"konnect,omitempty"`

	// Conditions describe the status of the Konnect entity.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// KongServiceList contains a list of Kong Services.
type KongServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KongService `json:"items"`
}
