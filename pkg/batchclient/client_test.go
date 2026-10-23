package batchclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
)

func TestSendIncludesClusterIdentifier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Cluster-Identifier"); got != "test-cluster" {
			t.Errorf("cluster identifier = %q, want test-cluster", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	hb := heartbeat.NewService(server.URL, "token", 0)
	hb.SetClusterIdentifier("test-cluster")
	client := &BatchClient{endpoint: server.URL, apiToken: "token", heartbeatService: hb, httpClient: server.Client()}
	if err := client.send([]any{"event"}); err != nil {
		t.Fatal(err)
	}
}
