package falco

import (
	"context"
	"encoding/json"
	"errors"
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

// FalcoPayload represents a Falco event as received from the Falco agent.
type FalcoPayload struct {
	Rule         string         `json:"rule"`
	Tags         []string       `json:"tags"`
	OutputFields map[string]any `json:"output_fields"`
}

// Route defines how events with a specific Falco tag are forwarded.
type Route struct {
	// Tag is the Falco event tag that triggers this route.
	Tag string
	// Client receives matched events.
	Client *batchclient.BatchClient
	// IsEnabled is called before routing; if it returns false the route is
	// skipped. A nil IsEnabled means the route is always active.
	IsEnabled func() bool
	// ShouldSkip is an optional per-route filter applied after the common
	// namespace filter. Return true to drop the event for this route.
	ShouldSkip func(FalcoPayload) bool
}

// This is how it works from a high-level:
//   - Falco sends a JSON object to the proxy via HTTP POST.
//   - Falco doesn't need an immediate success/failure response from the final target.
//   - The proxy must ensure eventual delivery to Aikido HTTP endpoint (with retries).
//   - The proxy adds a cluster token to authenticate itself against Aikido cloud.
//   - Events are routed to the appropriate batch client based on their Falco tags.
//
// Proxy implements manager.Runnable for integration with controller-runtime.
type Proxy struct {
	*logger.Service
	*models.AgentState

	listenPort int
	server     *http.Server
	routes     []Route
}

func NewProxy(logger *logger.Service, listenPort int, agentState *models.AgentState, routes []Route) *Proxy {
	return &Proxy{
		AgentState: agentState,
		Service:    logger,
		listenPort: listenPort,
		routes:     routes,
	}
}

// SetAPIToken propagates a new API token to all route clients.
func (p *Proxy) SetAPIToken(token string) {
	for _, r := range p.routes {
		r.Client.SetAPIToken(token)
	}
}

// Start integrates with the controller-runtime manager.
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/detection", p.handleRequest)

	p.server = &http.Server{
		Addr:    ":" + strconv.Itoa(p.listenPort),
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		p.LogInfo("falco event proxy listening")
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.LogError(err, "proxy server failed")
			errCh <- fmt.Errorf("proxy server failed: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		p.LogInfo("falco event proxy shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy shutdown error: %w", err)
		}

		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var errs []error
		for _, r := range p.routes {
			if err := r.Client.Close(closeCtx); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

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

	event, drop := p.parseAndFilter(body)
	if drop {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	for _, route := range p.routes {
		if !slices.Contains(event.Tags, route.Tag) {
			continue
		}
		if route.IsEnabled != nil && !route.IsEnabled() {
			continue
		}
		if route.ShouldSkip != nil && route.ShouldSkip(event) {
			p.LogInfo("event filtered by route", "tag", route.Tag, "rule", event.Rule)
			continue
		}
		if err := route.Client.SendContext(r.Context(), json.RawMessage(body)); err != nil {
			p.LogError(err, "failed to enqueue event", "tag", route.Tag)
			http.Error(w, "failed to enqueue event", http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
	if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
		p.LogError(err, "proxy could not respond to the client")
	}
}

// parseAndFilter parses the event body and applies common namespace-based filtering.
// Host-level events with no namespace field pass through unconditionally.
// Events from the agent namespace are always dropped.
// Customer-configured excluded/included namespace lists are also applied.
// Returns the parsed event and true if the event should be dropped.
func (p *Proxy) parseAndFilter(body []byte) (FalcoPayload, bool) {
	var event FalcoPayload
	if err := json.Unmarshal(body, &event); err != nil {
		p.LogError(err, "failed to unmarshal falco event")
		return event, true
	}

	nsI, ok := event.OutputFields["k8s.ns.name"]
	if !ok {
		return event, false
	}

	ns, ok := nsI.(string)
	if !ok {
		return event, false
	}

	if ns == p.GetAgentNamespace() {
		return event, true
	}

	if slices.Contains(p.GetExcludedNamespaces(), ns) {
		return event, true
	}

	includedNamespaces := p.GetIncludedNamespaces()
	if len(includedNamespaces) > 0 && !slices.Contains(includedNamespaces, ns) {
		return event, true
	}

	return event, false
}
