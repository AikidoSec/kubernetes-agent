package imagescache

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"

	"aikidoSec.kubernetesAgent/pkg/models"
)

// SBOM collector processed images cache
type ImagesCache struct {
	ProcessedImagesCache     map[string]struct{}
	ProcessedImagesCacheLock sync.RWMutex
}

func NewImagesCache() *ImagesCache {
	return &ImagesCache{
		ProcessedImagesCache:     make(map[string]struct{}),
		ProcessedImagesCacheLock: sync.RWMutex{},
	}
}

func (c *ImagesCache) IsImageProcessed(imageID string) bool {
	c.ProcessedImagesCacheLock.RLock()
	defer c.ProcessedImagesCacheLock.RUnlock()

	_, exists := c.ProcessedImagesCache[imageID]
	return exists
}

func (c *ImagesCache) MarkImageAsProcessed(imageID string) {
	c.ProcessedImagesCacheLock.Lock()
	defer c.ProcessedImagesCacheLock.Unlock()

	c.ProcessedImagesCache[imageID] = struct{}{}
}

func (c *ImagesCache) LoadFromScannedImages(scannedImages []models.ScannedImage) {
	c.ProcessedImagesCacheLock.Lock()
	defer c.ProcessedImagesCacheLock.Unlock()
	c.ProcessedImagesCache = make(map[string]struct{})

	for _, img := range scannedImages {
		c.ProcessedImagesCache[fmt.Sprintf("%s:%s", img.Image, img.Digest)] = struct{}{}
	}
}

func (c *ImagesCache) CalculateHash() (int64, error) {
	c.ProcessedImagesCacheLock.Lock()
	defer c.ProcessedImagesCacheLock.Unlock()

	var xorSum uint64 = 0

	for i, ref := range slices.Sorted(maps.Keys(c.ProcessedImagesCache)) {
		// Payload: "Index#image:digest", needs index for correct hash (+1 to match pg)
		payload := strconv.Itoa(i+1) + "#" + ref

		hash := md5.Sum([]byte(payload))
		hashString := hex.EncodeToString(hash[:])

		val, err := strconv.ParseUint(hashString[:16], 16, 64)
		if err != nil {
			return 0, err
		}

		// XOR aggregate of the hashes
		xorSum ^= val
	}

	// Cast to signed int64 to match pg
	return int64(xorSum), nil
}
