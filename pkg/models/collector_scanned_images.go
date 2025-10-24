package models

import (
	"encoding/json"
	"io"
	"time"
)

type ScannedImage struct {
	ID         int       `db:"id" json:"id"`
	SysGroupID int       `db:"sys_group_id" json:"sys_group_id"`
	ClusterID  int       `db:"cluster_id" json:"cluster_id"`
	Image      string    `db:"image" json:"image"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	ModifiedAt time.Time `db:"modified_at" json:"modified_at"`
}

func (p *ScannedImage) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(p)
}

func (p *ScannedImage) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(p)
}
