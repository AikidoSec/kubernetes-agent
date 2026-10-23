package heartbeat

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (s *Service) VerifyToken(ctx context.Context, clusterIdentifier string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIEndpoint+"/api/verifyToken", nil)
	if err != nil {
		return fmt.Errorf("error creating token verification request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.APIToken)
	req.Header.Set("X-Cluster-Identifier", clusterIdentifier)

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error verifying token: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("error closing token verification response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("token verification returned non-200 response: %d", res.StatusCode)
	}
	return nil
}
