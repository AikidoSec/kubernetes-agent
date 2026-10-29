package heartbeat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

func TestValidateToken(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/validateToken" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing bearer token")
				}

				if r.Header.Get("X-Shared-Token-Enabled") != "true" || r.Header.Get("X-Shared-Token-Cluster-Identifier") != "test-cluster" {
					t.Error("missing shared token routing headers")
				}

				if r.Header.Get("X-Cluster-Identifier") != "cluster-uid" {
					t.Error("missing cluster identifier header")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()

			state := models.NewEmptyAgentState()
			state.SetClusterIdentifier("cluster-uid")
			state.SetSharedTokenConfig(models.SharedTokenConfig{Enabled: true, ClusterIdentifier: "test-cluster"})

			s := NewService(server.URL, "test-token", 0, state)

			err := s.ValidateToken(context.Background())
			if (err != nil) != (status != http.StatusOK) {
				t.Fatalf("status %d: unexpected error: %v", status, err)
			}
		})
	}
}
