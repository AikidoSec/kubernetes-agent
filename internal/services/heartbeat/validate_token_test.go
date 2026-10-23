package heartbeat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
				if r.Header.Get("X-Cluster-Identifier") != "test-cluster" {
					t.Error("missing cluster identifier")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			s := NewService(server.URL, "test-token", 0)
			err := s.ValidateToken(context.Background(), "test-cluster")
			if (err != nil) != (status != http.StatusOK) {
				t.Fatalf("status %d: unexpected error: %v", status, err)
			}
		})
	}
}
