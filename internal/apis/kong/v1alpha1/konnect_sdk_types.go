package v1alpha1

// Mirrors sdk-konnect-go's models/components. The four enums are plain types here
// rather than validating ones; see doc.go.

// Destinations is an IP destination of incoming connections matched when using stream routing.
type Destinations struct {
	// A string representing an IP address or CIDR block, such as 192.168.1.1 or 192.168.0.0/16.
	IP *string `json:"ip"`
	// An integer representing a port number between 0 and 65535, inclusive.
	Port *int64 `json:"port"`
}

// Sources is an IP source of incoming connections matched when using stream routing.
type Sources struct {
	// A string representing an IP address or CIDR block, such as 192.168.1.1 or 192.168.0.0/16.
	IP *string `json:"ip"`
	// An integer representing a port number between 0 and 65535, inclusive.
	Port *int64 `json:"port"`
}

// HTTPSRedirectStatusCode is the status code Kong responds with when all properties of
// a Route match except the protocol.
type HTTPSRedirectStatusCode int64

// PathHandling controls how the Service path, Route path and requested path are
// combined when sending a request to the upstream.
type PathHandling string

// RouteJSONProtocols is a protocol a Route allows.
type RouteJSONProtocols string

// Protocol is the protocol used to communicate with the upstream.
type Protocol string
