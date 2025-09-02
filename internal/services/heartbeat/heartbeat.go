package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"aikidoSec.kubernetesAgent/pkg/models"
)

type Service struct {
	APIEndpoint    string
	APIToken       string
	isServerActive bool
	sendInterval   time.Duration
}

func NewService(apiEndpoint, apiToken string, sendInterval time.Duration) *Service {
	return &Service{
		APIEndpoint:  apiEndpoint,
		APIToken:     apiToken,
		sendInterval: sendInterval,
	}
}

func (s *Service) SendHeartbeat(ctx context.Context, agentVersion string) (models.HeartbeatResponse, error) {
	heartbeatResponse, err := s.sendHeartbeatRequest(ctx, agentVersion)
	if err != nil {
		s.isServerActive = false
		return models.HeartbeatResponse{}, fmt.Errorf("error sending heartbeat: %w", err)
	}

	s.isServerActive = true
	return heartbeatResponse, nil
}

func (s *Service) IsServerActive() bool {
	return s.isServerActive
}

func (s *Service) SetAPIToken(token string) {
	s.APIToken = token
}

func (s *Service) GetSendInterval() time.Duration {
	return s.sendInterval
}

func (s *Service) sendHeartbeatRequest(ctx context.Context, agentVersion string) (models.HeartbeatResponse, error) {
	heartbeatPayload := models.HeartbeatPayload{AgentVersion: agentVersion}

	payloadBytes, err := json.Marshal(&heartbeatPayload)
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("error marshalling heartbeat payload: %w", err)
	}
	payloadBody := strings.NewReader(string(payloadBytes))

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/heartbeat", s.APIEndpoint), payloadBody)

	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.APIToken)

	res, err := client.Do(req)
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("error sending heartbeat: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("error closing response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return models.HeartbeatResponse{}, fmt.Errorf("received non-200 response: %d", res.StatusCode)
	}

	var heartbeatResponse models.HeartbeatResponse
	if err := heartbeatResponse.FromJSON(res.Body); err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("error unmarshalling heartbeat: %w", err)
	}

	return heartbeatResponse, nil
}
