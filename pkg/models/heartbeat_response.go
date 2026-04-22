package models

import (
	"encoding/json"
	"io"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type HeartbeatResponse struct {
	Cluster            Cluster                   `json:"cluster"`
	Token              string                    `json:"token"`
	MonitoredResources []schema.GroupVersionKind `json:"monitoredResources"`
	ImageCacheHash     *int64                    `json:"imageCacheHash,omitempty"`
	EnabledThreatRules        []string                   `json:"enabled_threat_rules"`
	ThreatDetectionExceptions []ThreatDetectionException `json:"threat_detection_exceptions"`
}

func (h *HeartbeatResponse) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(h)
}

func (h *HeartbeatResponse) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(h)
}
