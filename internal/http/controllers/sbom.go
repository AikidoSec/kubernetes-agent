package controllers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"aikidoSec.kubernetesAgent/internal/services/sbom"
	"aikidoSec.kubernetesAgent/pkg/models"
)

type SBOMController struct {
	service *sbom.Service
	logger  *slog.Logger
}

func NewSBOMController(logger *slog.Logger, svc *sbom.Service) *SBOMController {
	return &SBOMController{
		service: svc,
		logger:  logger,
	}
}

func (c *SBOMController) RegisterRoutes(mux *http.ServeMux) {
	// SECURITY NOTE: These endpoints expose sensitive information including API tokens.
	// They should only be accessible from trusted sources (e.g., the SBOM collector pod).
	// Ensure proper network policies are in place to restrict access to these endpoints.
	mux.HandleFunc("GET /sbom-collector/config", c.GetCollectorConfig)
	// The /sbom-collector/token endpoint has been removed as it's redundant.
	// The API token is already included in the /sbom-collector/config response.
	mux.HandleFunc("GET /sbom-collector/image-status", c.GetImageProcessingStatus)
	mux.HandleFunc("POST /sbom-collector/image-status", c.SetImageProcessingStatus)
}

func (c *SBOMController) GetCollectorConfig(rw http.ResponseWriter, r *http.Request) {
	// Log access to this sensitive endpoint
	c.logger.Info("SBOM collector config requested",
		slog.String("remoteAddr", r.RemoteAddr),
		slog.String("userAgent", r.UserAgent()))

	cfg, err := c.service.HandleGetCollectorConfig(r.Context())
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

func (c *SBOMController) GetImageProcessingStatus(rw http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		http.Error(rw, "missing `image` from query parameters", http.StatusBadRequest)
		return
	}

	digest := r.URL.Query().Get("digest")
	if digest == "" {
		http.Error(rw, "missing `digest` from query parameters", http.StatusBadRequest)
		return
	}

	imageStatus, err := c.service.HandleGetImageProcessingStatus(r.Context(), image, digest)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error getting image processing status: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(rw).Encode(imageStatus); err != nil {
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

	err := c.service.HandleSetImageProcessingStatus(r.Context(), imageStatus)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error setting image processing status: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
