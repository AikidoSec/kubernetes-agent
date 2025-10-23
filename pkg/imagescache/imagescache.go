package imagescache

import "sync"

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
