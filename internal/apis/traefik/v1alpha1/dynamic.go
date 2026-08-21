package v1alpha1

// Types reachable from IngressRoute that live outside traefikio/v1alpha1 upstream:
//   - pkg/config/dynamic/http_config.go   RouterObservabilityConfig, Sticky, Cookie, BalancerStrategy
//   - pkg/types/domains.go                Domain
//   - pkg/observability/types/tracing.go  TracingVerbosity
//
// The toml, yaml and export tags are unused here but kept so a diff against upstream
// stays mechanical.

// RouterObservabilityConfig holds the observability configuration for a router.
type RouterObservabilityConfig struct {
	// AccessLogs enables access logs for this router.
	AccessLogs *bool `json:"accessLogs,omitempty" toml:"accessLogs,omitempty" yaml:"accessLogs,omitempty" export:"true"`
	// Metrics enables metrics for this router.
	Metrics *bool `json:"metrics,omitempty" toml:"metrics,omitempty" yaml:"metrics,omitempty" export:"true"`
	// Tracing enables tracing for this router.
	Tracing *bool `json:"tracing,omitempty" toml:"tracing,omitempty" yaml:"tracing,omitempty" export:"true"`
	// TraceVerbosity defines the verbosity level of the tracing for this router.
	// +kubebuilder:validation:Enum=minimal;detailed
	// +kubebuilder:default=minimal
	TraceVerbosity TracingVerbosity `json:"traceVerbosity,omitempty" toml:"traceVerbosity,omitempty" yaml:"traceVerbosity,omitempty" export:"true"`
}

// Sticky holds the sticky sessions configuration.
type Sticky struct {
	// Cookie defines the sticky cookie configuration.
	Cookie *Cookie `json:"cookie,omitempty" toml:"cookie,omitempty" yaml:"cookie,omitempty" label:"allowEmpty" file:"allowEmpty" kv:"allowEmpty" export:"true"`
}

// Cookie holds the sticky configuration based on cookie.
type Cookie struct {
	// Name defines the Cookie name.
	Name string `json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty" export:"true"`
	// Secure defines whether the cookie can only be transmitted over an encrypted connection (i.e. HTTPS).
	Secure bool `json:"secure,omitempty" toml:"secure,omitempty" yaml:"secure,omitempty" export:"true"`
	// HTTPOnly defines whether the cookie can be accessed by client-side APIs, such as JavaScript.
	HTTPOnly bool `json:"httpOnly,omitempty" toml:"httpOnly,omitempty" yaml:"httpOnly,omitempty" export:"true"`
	// SameSite defines the same site policy.
	// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
	// +kubebuilder:validation:Enum=none;lax;strict;None;Lax;Strict
	SameSite string `json:"sameSite,omitempty" toml:"sameSite,omitempty" yaml:"sameSite,omitempty" export:"true"`
	// MaxAge defines the number of seconds until the cookie expires.
	// When set to a negative number, the cookie expires immediately.
	// When set to zero, the cookie never expires.
	MaxAge int `json:"maxAge,omitempty" toml:"maxAge,omitempty" yaml:"maxAge,omitempty" export:"true"`
	// Path defines the path that must exist in the requested URL for the browser to send the Cookie header.
	// When not provided the cookie will be sent on every request to the domain.
	// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#pathpath-value
	Path *string `json:"path,omitempty" toml:"path,omitempty" yaml:"path,omitempty" export:"true"`
	// Domain defines the host to which the cookie will be sent.
	// More info: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value
	Domain string `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
}

type BalancerStrategy string

const (
	// BalancerStrategyWRR is the weighted round-robin strategy.
	BalancerStrategyWRR BalancerStrategy = "wrr"
	// BalancerStrategyP2C is the power of two choices strategy.
	BalancerStrategyP2C BalancerStrategy = "p2c"
	// BalancerStrategyHRW is the highest random weight strategy.
	BalancerStrategyHRW BalancerStrategy = "hrw"
	// BalancerStrategyLeastTime is the least-time strategy.
	BalancerStrategyLeastTime BalancerStrategy = "leasttime"
)

// Domain holds a domain name with SANs.
type Domain struct {
	// Main defines the main domain name.
	Main string `description:"Default subject name." json:"main,omitempty" toml:"main,omitempty" yaml:"main,omitempty"`
	// SANs defines the subject alternative domain names.
	SANs []string `description:"Subject alternative names." json:"sans,omitempty" toml:"sans,omitempty" yaml:"sans,omitempty"`
}

type TracingVerbosity string

const (
	MinimalVerbosity  TracingVerbosity = "minimal"
	DetailedVerbosity TracingVerbosity = "detailed"
)
