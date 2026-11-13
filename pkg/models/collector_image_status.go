package models

type CollectorImageStatus struct {
	Image            string `json:"image"`
	Digest           string `json:"digest"`
	Architecture     string `json:"architecture"`
	IsProcessed      bool   `json:"isProcessed"`
	MirrorRepository string `json:"mirrorRepository"`
	IsReserved       bool   `json:"isReserved"`
}

// CollectorImageKey identifies an image processed by the SBOM collector.
// It must match the key used by the Kubernetes API to calculate the v2 scanned images cache hash.
func CollectorImageKey(image, digest, architecture string) string {
	return image + ":" + digest + ":" + architecture
}
