package models

type CollectorImageStatus struct {
	Image       string `json:"image"`
	IsProcessed bool   `json:"isProcessed"`
}
