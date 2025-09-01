package models

import (
	"encoding/json"
	"io"
	"time"
)

type EventType string

const (
	ModifiedEventType = "modified"
	DeletedEventType  = "deleted"
)

type AssetPayload struct {
	ObjectUID string    `json:"object_uid"`
	Metadata  string    `json:"metadata"`
	EventType EventType `json:"event_type"`
	EventTime time.Time `json:"event_time"`
}

func (p *AssetPayload) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(p)
}

func (p *AssetPayload) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(p)
}
