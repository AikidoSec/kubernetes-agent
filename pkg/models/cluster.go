package models

import (
	"encoding/json"
	"io"
)

type Cluster struct {
	ID                  int      `json:"id"`
	SysGroupID          int      `json:"sys_group_id"`
	Name                string   `json:"name"`
	ExcludedNamespaces  []string `json:"excluded_namespaces"`
	DesiredAgentVersion string   `json:"desired_agent_version"`
}

func (c *Cluster) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(c)
}

func (c *Cluster) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(c)
}
