package controllers

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"aikidoSec.kubernetesAgent/internal/services/manager"
	"aikidoSec.kubernetesAgent/pkg/imagescache"
	"aikidoSec.kubernetesAgent/pkg/models"
)

type SBOMController struct {
	service     *manager.Service
	logger      *slog.Logger
	imagesCache *imagescache.ImagesCache
}

func NewSBOMController(logger *slog.Logger, service *manager.Service, cache *imagescache.ImagesCache) *SBOMController {
	return &SBOMController{
		service:     service,
		logger:      logger,
		imagesCache: cache,
	}
}

func (c *SBOMController) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sbom-collector/config", c.GetCollectorConfig)
	mux.HandleFunc("GET /sbom-collector/token", c.GetCollectorToken)
	mux.HandleFunc("GET /sbom-collector/image-status/{image}", c.GetImageProcessingStatus)
	mux.HandleFunc("POST /sbom-collector/image-status", c.SetImageProcessingStatus)
	mux.HandleFunc("POST /sbom-collector/errors", c.ReportCollectorErrors)
}

func (c *SBOMController) GetCollectorConfig(rw http.ResponseWriter, r *http.Request) {
	cfg, err := c.service.GenerateCollectorConfig(r.Context())
	if err != nil {
		http.Error(rw, fmt.Sprintf("error generating SBOM collector config: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(rw).Encode(cfg); err != nil {
		http.Error(rw, fmt.Sprintf("error encoding response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
}

func (c *SBOMController) GetCollectorToken(rw http.ResponseWriter, _ *http.Request) {
	t := c.service.GetAPIToken()
	rw.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(rw).Encode(models.CollectorToken{Token: t}); err != nil {
		http.Error(rw, fmt.Sprintf("error encoding response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
}

func (c *SBOMController) GetImageProcessingStatus(rw http.ResponseWriter, r *http.Request) {
	image := r.PathValue("image")
	if image == "" {
		http.Error(rw, "missing image in path", http.StatusBadRequest)
		return
	}

	isProcessed := c.imagesCache.IsImageProcessed(image)

	rw.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(rw).Encode(models.CollectorImageStatus{
		Image:       image,
		IsProcessed: isProcessed,
	}); err != nil {
		http.Error(rw, fmt.Sprintf("error encoding response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
}

func (c *SBOMController) SetImageProcessingStatus(rw http.ResponseWriter, r *http.Request) {
	var imageStatus models.CollectorImageStatus
	if err := json.NewDecoder(r.Body).Decode(&imageStatus); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}

	if imageStatus.Image == "" {
		http.Error(rw, "image field must be non-empty", http.StatusBadRequest)
		return
	}

	c.imagesCache.MarkImageAsProcessed(imageStatus.Image)
	rw.WriteHeader(http.StatusOK)
}

func (c *SBOMController) ReportCollectorErrors(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		http.Error(rw, "Unsupported Content-Encoding", http.StatusUnsupportedMediaType)
		return
	}

	// Wrap the body with a gzip reader
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(rw, "Failed to create gzip reader", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := gz.Close(); err != nil {
			c.logger.Error("error closing gzip reader", slog.String("error", err.Error()))
		}
	}()

	var payload models.AgentError
	if err := json.NewDecoder(gz).Decode(&payload); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := c.service.HandleCollectorError(r.Context(), payload); err != nil {
		http.Error(rw, fmt.Sprintf("error handling collector errors: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
