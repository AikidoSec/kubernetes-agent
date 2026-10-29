package batchclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

func TestSendIncludesSharedTokenConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Shared-Token-Enabled") != "true" || r.Header.Get("X-Shared-Token-Cluster-Identifier") != "test-cluster" {
			t.Error("missing shared token routing headers")
		}
		if r.Header.Get("X-Cluster-Identifier") != "cluster-uid" {
			t.Error("missing cluster identifier header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state := models.NewEmptyAgentState()
	state.SetClusterIdentifier("cluster-uid")
	state.SetSharedTokenConfig(models.SharedTokenConfig{Enabled: true, ClusterIdentifier: "test-cluster"})

	client := &BatchClient{endpoint: server.URL, apiToken: "token", agentState: state, httpClient: server.Client()}
	if err := client.send([]any{"event"}); err != nil {
		t.Fatal(err)
	}
}
