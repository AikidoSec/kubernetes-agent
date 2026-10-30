package heartbeat

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func (s *Service) ValidateStartupToken(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIEndpoint+"/api/validateStartupToken", nil)
	if err != nil {
		return fmt.Errorf("error creating token validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.APIToken)
	req.Header.Set("X-Cluster-Identifier", s.GetClusterIdentifier())
	req.Header.Set("X-Shared-Token-Enabled", s.GetSharedTokenEnabled())
	req.Header.Set("X-Shared-Token-Cluster-Identifier", s.GetSharedTokenClusterIdentifier())

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error validating token: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("error closing token validation response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(res.Body, 8*1024))
		if err != nil {
			return fmt.Errorf("startup token validation failed (HTTP %s): could not read API response: %w", res.Status, err)
		}
		return fmt.Errorf("startup token validation failed (HTTP %s): %s", res.Status, body)
	}
	return nil
}
