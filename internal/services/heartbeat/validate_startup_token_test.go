package heartbeat

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

func TestValidateStartupToken(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/validateStartupToken" {
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
				if status != http.StatusOK {
					_, _ = fmt.Fprint(w, "API validation error")
				}
			}))
			defer server.Close()

			state := models.NewEmptyAgentState()
			state.SetClusterIdentifier("cluster-uid")
			state.SetSharedTokenConfig(models.SharedTokenConfig{Enabled: true, ClusterIdentifier: "test-cluster"})

			s := NewService(server.URL, "test-token", 0, state)

			err := s.ValidateStartupToken(context.Background())
			if (err != nil) != (status != http.StatusOK) {
				t.Fatalf("status %d: unexpected error: %v", status, err)
			}
			if status != http.StatusOK {
				want := fmt.Sprintf("startup token validation failed (HTTP %d %s): API validation error", status, http.StatusText(status))
				if err.Error() != want {
					t.Fatalf("error = %q, want %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidateStartupTokenBoundsErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, strings.Repeat("x", 16*1024))
	}))
	defer server.Close()
	s := NewService(server.URL, "token", 0, models.NewEmptyAgentState())
	err := s.ValidateStartupToken(context.Background())
	want := "startup token validation failed (HTTP 500 Internal Server Error): " + strings.Repeat("x", 8*1024)
	if err == nil || err.Error() != want {
		t.Fatal("expected the logged response body to be limited to 8 KiB")
	}
}
