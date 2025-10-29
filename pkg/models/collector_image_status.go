package models

type CollectorImageStatus struct {
	Image       string `json:"image"`
	Digest      string `json:"digest"`
	IsProcessed bool   `json:"isProcessed"`
}
