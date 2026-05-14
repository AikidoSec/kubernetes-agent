package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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

// ReportError sends an error to the output client and logs it as well
func (s *Service) ReportError(ctx context.Context, err error, message string, errorType string, args ...any) {
	if err == nil {
		return
	}

	// These errors might be caused by the automatic update process stopping the agent
	if strings.Contains(err.Error(), "context canceled") {
		return
	}

	s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)

	s.SendError(ctx, err, errorType, args...)
}

// SendError sends an error to the output client
func (s *Service) SendError(ctx context.Context, err error, errorType string, args ...any) {
	// Build error message as JSON
	builder := strings.Builder{}
	builder.WriteString("{\"message\":")
	errJSON, marshalErr := json.Marshal(err.Error())
	if marshalErr != nil {
		_, _ = fmt.Fprintf(&builder, `"%v"`, err.Error())
	} else {
		builder.WriteString(string(errJSON))
	}

	for i := 0; i < len(args)-1; i += 2 {
		if i+1 >= len(args) {
			break
		}

		key, ok := args[i].(string)
		if !ok {
			continue
		}
		builder.WriteString(",\"")
		builder.WriteString(key)
		builder.WriteString("\":")

		argValue, marshalErr := json.Marshal(args[i+1])
		if marshalErr != nil {
			_, _ = fmt.Fprintf(&builder, `"%v"`, args[i+1])
			continue
		}
		builder.WriteString(string(argValue))
	}
	builder.WriteString("}")
	errorMessage := builder.String()

	if err := s.OutputClient.SendContext(ctx, models.AgentError{
		Error:     errorMessage,
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
