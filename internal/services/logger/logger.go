package logger

import (
	"context"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/go-logr/logr"
)

type Service struct {
	logger       logr.Logger
	OutputClient *batchclient.BatchClient
}

func NewService(logger logr.Logger, outputClient *batchclient.BatchClient) *Service {
	return &Service{
		logger:       logger,
		OutputClient: outputClient,
	}
}

func (s *Service) ReportError(ctx context.Context, err error, message string, errorType string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Error(err, message, args...)

	if err := s.OutputClient.SendContext(ctx, models.AgentError{
		Error:     fmt.Sprintf("%s: %s", message, err.Error()),
		ErrorType: errorType,
		SeenAt:    time.Now().UTC(),
	}); err != nil {
		s.logger.Error(err, "error sending error report to API")
	}
}

func (s *Service) LogError(err error, message string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Error(err, message, args...)
}

func (s *Service) LogInfo(message string, args ...any) {
	s.logger.Info(message, args...)
}

func (s *Service) SetAPIToken(token string) {
	s.OutputClient.SetAPIToken(token)
}

func (s *Service) GetLogger() logr.Logger {
	return s.logger
}

func (s *Service) Close(ctx context.Context) {
	if err := s.OutputClient.Close(ctx); err != nil {
		s.logger.Error(err, "error closing output client")
	}
}
