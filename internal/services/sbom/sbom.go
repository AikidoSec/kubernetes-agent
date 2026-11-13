package sbom

import (
	"context"
	"time"

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
		ClusterIdentifier:          s.GetClusterIdentifier(),
		SharedToken:                s.GetSharedTokenConfig(),
		APIHost:                    s.GetAPIEndpoint(),
		ExcludedNamespaces:         s.GetExcludedNamespaces(),
		IncludedNamespaces:         s.GetIncludedNamespaces(),
		ControllerCacheSyncTimeout: s.GetControllerCacheSyncTimeout(),
		APIToken:                   s.GetAPIToken(),
		Namespace:                  s.GetAgentNamespace(),
		ServiceAccountName:         serviceAccountName,
		ServiceAccountPullSecrets:  imagePullSecrets,
	}, nil
}

func (s *Service) HandleGetImageProcessingStatus(_ context.Context, image, digest, architecture string) (models.CollectorImageStatus, error) {
	imageKey := models.CollectorImageKey(image, digest, architecture)

	// Images scanned before the architecture was reported are stored without it, so they count as processed for every architecture.
	isProcessed := s.imagesCache.IsImageProcessed(imageKey) || (architecture != "" && s.imagesCache.IsImageProcessed(models.CollectorImageKey(image, digest, "")))
	mirrorRepository := s.GetImageMirrorMapping(image)
	status := models.CollectorImageStatus{
		Image:            image,
		Architecture:     architecture,
		IsProcessed:      isProcessed,
		MirrorRepository: mirrorRepository,
	}

	if isProcessed {
		return status, nil
	}

	reserved := s.TryReserveCollectorImageProcessing(imageKey, time.Now().Add(15*time.Minute))
	if !reserved {
		status.IsReserved = true
	}

	return status, nil
}

func (s *Service) HandleSetImageProcessingStatus(_ context.Context, imageStatus models.CollectorImageStatus) error {
	s.imagesCache.MarkImageAsProcessed(models.CollectorImageKey(imageStatus.Image, imageStatus.Digest, imageStatus.Architecture))
	return nil
}
