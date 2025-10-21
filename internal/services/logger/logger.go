package logger

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
)

type Service struct {
	logger       *slog.Logger
	OutputClient *batchclient.BatchClient
}

func NewService(logger *slog.Logger, outputClient *batchclient.BatchClient) *Service {
	return &Service{
		logger:       logger,
		OutputClient: outputClient,
	}
}

func (s *Service) ReportError(ctx context.Context, err error, message string, errorType string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)

	if err := s.OutputClient.SendContext(ctx, models.AgentError{
		Error:     fmt.Sprintf("%s: %s", message, err.Error()),
		ErrorType: errorType,
		SeenAt:    time.Now().UTC(),
	}); err != nil {
		s.logger.Error(fmt.Sprintf("error sending agent errors: %s", err.Error()), args...)
	}
}

func (s *Service) LogError(err error, message string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)
}

func (s *Service) LogInfo(message string, args ...any) {
	s.logger.Info(message, args...)
}

func (s *Service) LogWarning(err error, message string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Warn(fmt.Sprintf("%s: %s", message, err.Error()), args...)
}

func (s *Service) SetAPIToken(token string) {
	s.OutputClient.SetAPIToken(token)
}

func (s *Service) GetLogger() *slog.Logger {
	return s.logger
}

func (s *Service) Close(ctx context.Context) {
	if err := s.OutputClient.Close(ctx); err != nil {
		s.logger.Error("error closing output client", slog.String("error", err.Error()))
	}
}
