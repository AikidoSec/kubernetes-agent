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

	var serviceAccountName string
	var imagePullSecrets []string
	if sa := s.GetSBOMCollectorServiceAccount(); sa != nil {
		serviceAccountName = sa.Name

		imagePullSecrets = make([]string, len(sa.ImagePullSecrets))
		for i, secret := range sa.ImagePullSecrets {
			imagePullSecrets[i] = secret.Name
		}
	}

	return models.CollectorConfig{
		APIHost:                    s.GetAPIEndpoint(),
		ExcludedNamespaces:         excludedNamespaces,
		ControllerCacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
		APIToken:                   s.GetAPIToken(),
		Namespace:                  s.GetAgentNamespace(),
		ServiceAccountName:         serviceAccountName,
		ServiceAccountPullSecrets:  imagePullSecrets,
	}, nil
}

func (s *Service) HandleGetImageProcessingStatus(_ context.Context, image, digest string) (bool, error) {
	return s.imagesCache.IsImageProcessed(fmt.Sprintf("%s:%s", image, digest)), nil
}

func (s *Service) HandleSetImageProcessingStatus(_ context.Context, imageStatus models.CollectorImageStatus) error {
	s.imagesCache.MarkImageAsProcessed(fmt.Sprintf("%s:%s", imageStatus.Image, imageStatus.Digest))
	return nil
}

func (s *Service) HandleReportCollectorError(ctx context.Context, error models.AgentError) error {
	s.logger.SendError(ctx, fmt.Errorf("%s", error.Error), error.ErrorType)
	return nil
}
