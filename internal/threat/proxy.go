package threat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
)

type FalcoPayload struct {
	OutputFields map[string]any `json:"output_fields"`
}

// This is how it works from a high-level
//   - Falco sends a JSON object to the proxy via HTTP POST.
//   - Falco doesn’t need an immediate success/failure response from the final target.
//   - The proxy must ensure eventual delivery to Aikido HTTP endpoint (with retries).
//   - The proxy adds a cluster token to authenticate itself against Aikido cloud
//
// Proxy implements manager.Runnable for integration with controller-runtime
type Proxy struct {
	*logger.Service
	*models.AgentState

	listenPort int
	server     *http.Server
	queue      chan threatDetection
}

// JSON representation as received from falco and as forwarded to Aikido Cloud
type threatDetection []byte

func NewProxyServer(logger *logger.Service, listenPort int, agentState *models.AgentState) *Proxy {
	return &Proxy{
		AgentState: agentState,
		Service:    logger,
		listenPort: listenPort,
		queue:      make(chan threatDetection, 1000), // buffered queue
	}
}

// Start integrates with controller-runtime manager
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/detection", p.handleRequest)

	p.server = &http.Server{
		Addr:    ":" + strconv.Itoa(p.listenPort),
		Handler: mux,
	}

	// Worker goroutine for delivering queued events
	go p.deliveryManager(ctx)

	// HTTP server goroutine
	errCh := make(chan error, 1)
	go func() {
		p.LogInfo("Threat Detection Proxy listening")
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.LogError(err, "proxy server failed")
			errCh <- fmt.Errorf("proxy server failed: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		p.LogInfo("Threat Detection Proxy shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy shutdown error: %w", err)
		}
		return nil
	}
}

// handleRequest: receive data from falco agent, enqueue for delivery, and return immediately
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	body, err := io.ReadAll(r.Body)
	defer func() {
		err := r.Body.Close()
		if err != nil {
			p.LogError(err, "proxy could not close body")
		}
	}()
	if err != nil {
		p.LogError(err, "failed to read body")
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	select {
	case p.queue <- body:
		w.WriteHeader(http.StatusAccepted)
		_, err := w.Write([]byte(`{"status":"queued"}`))
		if err != nil {
			p.LogError(err, "proxy could not respond to the client")
		}
	default:
		// This will show up in Falco logs, should we ever overflow
		http.Error(w, "Aikido Kubernetes Agent Queue Full", http.StatusServiceUnavailable)
	}
}

// deliveryManager continuously retries sending events to the target endpoint
func (p *Proxy) deliveryManager(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Stop the
			return
		case body := <-p.queue:
			if !p.IsThreatDetectionEnabled() {
				continue
			}
			if p.ShouldFilterOutEvent(ctx, body) {
				p.LogInfo("filtered out event", "event_body", string(body))
				continue
			}
			p.deliverWithRetry(ctx, body)
		}
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

// deliverWithRetry tries to POST with exponential backoff until success or shutdown
func (p *Proxy) deliverWithRetry(ctx context.Context, body threatDetection) {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	// later we can try to share the client
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/threats/detection", p.GetAPIEndpoint()), bytes.NewReader(body))
		if err != nil {
			p.LogError(err, "failed to create request")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+p.GetAPIToken())

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if err := resp.Body.Close(); err != nil {
				p.LogError(err, "proxy could not close body to upstream")
			}
			p.LogInfo("Successfully delivered object")
			return
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				p.LogError(err, "proxy could not close body to upstream")
			}
		}

		// Delivery failed, let's do backoff
		select {
		case <-ctx.Done():
			p.LogInfo("Cancelled delivery retry due to shutdown")
			return
		case <-time.After(backoff):
			// Exponential backoff
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}
