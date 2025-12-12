package sbom

import (
	"context"
	"fmt"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/imagescache"
	"aikidoSec.kubernetesAgent/pkg/models"
)

// Service handles the incoming requests for the SBOM controller.
type Service struct {
	*models.AgentState
	logger      *logger.Service
	imagesCache *imagescache.ImagesCache
}

func NewService(logger *logger.Service, agentState *models.AgentState, cache *imagescache.ImagesCache) *Service {
	return &Service{
		AgentState:  agentState,
		logger:      logger,
		imagesCache: cache,
	}
}

func (s *Service) HandleGetCollectorConfig(_ context.Context) (models.CollectorConfig, error) {
	// Include the agent namespace in the excluded namespaces to prevent scanning itself
	excludedNamespaces := make([]string, len(s.GetExcludedNamespaces()))
	copy(excludedNamespaces, s.GetExcludedNamespaces())
	excludedNamespaces = append(excludedNamespaces, s.GetAgentNamespace())

	return models.CollectorConfig{
		APIHost:                    s.GetAPIEndpoint(),
		ExcludedNamespaces:         excludedNamespaces,
		ControllerCacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
		APIToken:                   s.GetAPIToken(),
	}, nil
}

func (s *Service) HandleGetImageProcessingStatus(_ context.Context, image, digest string) (models.CollectorImageStatus, error) {
	isProcessed := s.imagesCache.IsImageProcessed(fmt.Sprintf("%s:%s", image, digest))
	mirrorSource := s.GetImageMirrorMapping(image)

	return models.CollectorImageStatus{
		Image:        image,
		IsProcessed:  isProcessed,
		MirrorSource: mirrorSource,
	}, nil
}

func (s *Service) HandleSetImageProcessingStatus(_ context.Context, imageStatus models.CollectorImageStatus) error {
	s.imagesCache.MarkImageAsProcessed(fmt.Sprintf("%s:%s", imageStatus.Image, imageStatus.Digest))
	return nil
}

func (s *Service) HandleReportCollectorError(ctx context.Context, error models.AgentError) error {
	s.logger.ReportError(ctx, fmt.Errorf("%s", error.Error), "SBOM collector error", error.ErrorType)
	return nil
}
