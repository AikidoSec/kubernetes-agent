package models

import (
	"encoding/json"
	"io"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ThreatDetectionHeartbeat struct {
	Enabled    bool                        `json:"enabled"`
	Rules      *[]string                   `json:"rules"`
	Exceptions *[]ThreatDetectionException `json:"exceptions"`
}

type RuntimeSCAHeartbeat struct {
	Enabled bool `json:"enabled"`
}

type HeartbeatResponse struct {
	Cluster            Cluster                   `json:"cluster"`
	Token              string                    `json:"token"`
	MonitoredResources []schema.GroupVersionKind `json:"monitoredResources"`
	ImageCacheHash     *int64                    `json:"imageCacheHash,omitempty"`
	ThreatDetection    ThreatDetectionHeartbeat  `json:"threat_detection"`
	RuntimeSCA         RuntimeSCAHeartbeat       `json:"runtime_sca"`
}

func (h *HeartbeatResponse) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(h)
}

func (h *HeartbeatResponse) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(h)
}
