package controllers

import (
	"compress/gzip"
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
	mux.HandleFunc("GET /sbom-collector/config", c.GetCollectorConfig)
	mux.HandleFunc("GET /sbom-collector/token", c.GetCollectorToken)
	mux.HandleFunc("GET /sbom-collector/image-status", c.GetImageProcessingStatus)
	mux.HandleFunc("POST /sbom-collector/image-status", c.SetImageProcessingStatus)
	mux.HandleFunc("POST /sbom-collector/errors", c.ReportCollectorError)
}

func (c *SBOMController) GetCollectorConfig(rw http.ResponseWriter, r *http.Request) {
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

func (c *SBOMController) GetCollectorToken(rw http.ResponseWriter, _ *http.Request) {
	t := c.service.GetAPIToken()
	rw.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(rw).Encode(models.CollectorToken{Token: t}); err != nil {
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

func (c *SBOMController) ReportCollectorError(rw http.ResponseWriter, r *http.Request) {
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

	if err := c.service.HandleReportCollectorError(r.Context(), payload); err != nil {
		http.Error(rw, fmt.Sprintf("error handling collector errors: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
