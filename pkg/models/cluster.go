package models

import (
	"encoding/json"
	"io"
)

type Cluster struct {
	ID                          int      `json:"id"`
	SysGroupID                  int      `json:"sys_group_id"`
	Name                        string   `json:"name"`
	ExcludedNamespaces          []string `json:"excluded_namespaces"`
	IncludedNamespaces          []string `json:"included_namespaces"`
	DesiredAgentVersion         string   `json:"desired_agent_version"`
	DesiredSBOMCollectorVersion string   `json:"desired_sbom_collector_version"`
	SBOMCollectorEnabled        bool     `json:"sbom_collector_enabled"`
	ThreatDetectionEnabled      bool     `json:"threat_detection_enabled"`
}

func (c *Cluster) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(c)
}

func (c *Cluster) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(c)
}
