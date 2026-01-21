package models

import (
	"encoding/json"
	"io"
)

type HeartbeatPayload struct {
	AgentVersion        string `json:"agent_version"`
	CollectorVersion    string `json:"collector_version"`
	IsInitialHeartbeat  bool   `json:"is_initial_heartbeat"`
	ClusterIdentifier   string `json:"cluster_identifier"`
	Metrics             string `json:"metrics"`
	NamespaceEvents     string `json:"namespace_events"`
	HelmChartsVersion   string `json:"helm_charts_version"`
	AgentDeploymentName string `json:"agent_deployment_name"`
	AgentNamespace      string `json:"agent_namespace"`
}

func (p *HeartbeatPayload) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(p)
}

func (p *HeartbeatPayload) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(p)
}
