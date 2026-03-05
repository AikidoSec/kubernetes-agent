package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
)

type FalcoPayload struct {
	OutputFields map[string]any `json:"output_fields"`
}

// This is how it works from a high-level
//   - Falco sends a JSON object to the proxy via HTTP POST.
//   - Falco doesn't need an immediate success/failure response from the final target.
//   - The proxy must ensure eventual delivery to Aikido HTTP endpoint (with retries).
//   - The proxy adds a cluster token to authenticate itself against Aikido cloud
//
// Proxy implements manager.Runnable for integration with controller-runtime
type Proxy struct {
	*logger.Service
	*models.AgentState

	listenPort  int
	server      *http.Server
	batchClient *batchclient.BatchClient
}

// JSON representation as received from falco and as forwarded to Aikido Cloud
type threatDetection []byte

func NewProxyServer(logger *logger.Service, listenPort int, agentState *models.AgentState, batchClient *batchclient.BatchClient) *Proxy {
	return &Proxy{
		AgentState:  agentState,
		Service:     logger,
		listenPort:  listenPort,
		batchClient: batchClient,
	}
}

func (p *Proxy) SetAPIToken(token string) {
	p.batchClient.SetAPIToken(token)
}

// Start integrates with controller-runtime manager
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/detection", p.handleRequest)

	p.server = &http.Server{
		Addr:    ":" + strconv.Itoa(p.listenPort),
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		p.LogInfo("threat detection proxy listening")
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.LogError(err, "proxy server failed")
			errCh <- fmt.Errorf("proxy server failed: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		p.LogInfo("threat detection proxy shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy shutdown error: %w", err)
		}

		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return p.batchClient.Close(closeCtx)
	}
}

// handleRequest: receive data from falco agent, filter, enqueue for batched delivery, and return immediately
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	body, err := io.ReadAll(r.Body)
	defer func() {
		if err := r.Body.Close(); err != nil {
			p.LogError(err, "proxy could not close body")
		}
	}()
	if err != nil {
		p.LogError(err, "failed to read body")
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	if !p.IsThreatDetectionEnabled() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if p.ShouldFilterOutEvent(r.Context(), body) {
		p.LogInfo("filtered out event", "event_body", string(body))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err := p.batchClient.SendContext(r.Context(), json.RawMessage(body)); err != nil {
		p.LogError(err, "failed to enqueue threat event")
		http.Error(w, "failed to enqueue threat event", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
		p.LogError(err, "proxy could not respond to the client")
	}
}

// ShouldFilterOutEvent checks if the event should be filtered out based on namespace.
// Host-level events with no namespace field pass through unconditionally.
// Events from the agent namespace are always dropped.
// Customer-configured excluded/included namespace lists are also applied.
func (p *Proxy) ShouldFilterOutEvent(_ context.Context, body threatDetection) bool {
	var falcoEvent FalcoPayload
	err := json.Unmarshal(body, &falcoEvent)
	if err != nil {
		p.LogError(err, "failed to unmarshal falco event")
		return true
	}

	nsI, ok := falcoEvent.OutputFields["k8smeta.ns.name"]
	if !ok {
		nsI, ok = falcoEvent.OutputFields["k8s.ns.name"]
	}
	if !ok {
		return false
	}

	ns, ok := nsI.(string)
	if !ok {
		return false
	}

	if ns == p.GetAgentNamespace() {
		return true
	}

	if slices.Contains(p.GetExcludedNamespaces(), ns) {
		return true
	}

	includedNamespaces := p.GetIncludedNamespaces()
	if len(includedNamespaces) > 0 && !slices.Contains(includedNamespaces, ns) {
		return true
	}

	return false
}
