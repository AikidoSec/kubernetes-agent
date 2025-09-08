package models

import (
	"encoding/json"
	"io"
)

type HeartbeatPayload struct {
	AgentVersion       string `json:"agent_version"`
	IsInitialHeartbeat bool   `json:"is_initial_heartbeat"`
	ClusterIdentifier  string `json:"cluster_identifier"`
}

func (p *HeartbeatPayload) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(p)
}

func (p *HeartbeatPayload) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(p)
}
