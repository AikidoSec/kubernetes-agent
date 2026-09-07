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
	"strings"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
)

// Event represents a Falco event as received from the Falco agent.
type Event struct {
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
	ShouldSkip func(Event) bool
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

	listenPort               int
	server                   *http.Server
	routes                   []Route
	ignoredImageRepositories []string
	redactor                 *Redactor
}

func NewProxy(logger *logger.Service, listenPort int, agentState *models.AgentState, ignoredImageRepositories []string, routes []Route, redactor *Redactor) *Proxy {
	return &Proxy{
		AgentState:               agentState,
		Service:                  logger,
		listenPort:               listenPort,
		routes:                   routes,
		ignoredImageRepositories: ignoredImageRepositories,
		redactor:                 redactor,
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
		Addr:              ":" + strconv.Itoa(p.listenPort),
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		p.LogInfo("falco event proxy listening")
		if err := p.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB — Falco events are typically <16KB
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

	raw, event, err := parseEvent(body)
	if err != nil {
		p.LogError(err, "failed to unmarshal falco event")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if p.shouldDrop(event) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := redactSecrets(raw, p.redactor); err != nil {
		p.LogError(err, "failed to redact secrets, dropping event to avoid leaking plaintext")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	sanitized, err := stripAikidoTags(raw, event.Tags)
	if err != nil {
		p.LogError(err, "failed to strip aikido tags")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	p.GetLogger().Debug("event received", "rule", event.Rule, "tags", event.Tags)

	if !hasAikidoTag(event.Tags) {
		p.LogWarning(fmt.Errorf("rule %q fired with no aikido: routing tag — event will not be forwarded", event.Rule), "misconfigured rule detected")
	}

	for _, route := range p.routes {
		if !slices.Contains(event.Tags, route.Tag) {
			p.LogInfo("event skipped: tag not matched", "rule", event.Rule, "event_tags", event.Tags, "route_tag", route.Tag)
			continue
		}
		if route.IsEnabled != nil && !route.IsEnabled() {
			p.LogInfo("event skipped: route not enabled", "rule", event.Rule, "route_tag", route.Tag)
			continue
		}
		if route.ShouldSkip != nil && route.ShouldSkip(event) {
			p.LogInfo("event skipped: filtered by route", "rule", event.Rule, "route_tag", route.Tag)
			continue
		}
		if err := route.Client.SendContext(r.Context(), sanitized); err != nil {
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

func parseEvent(body []byte) (map[string]json.RawMessage, Event, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, Event{}, err
	}

	var event Event
	if v, ok := raw["rule"]; ok {
		if err := json.Unmarshal(v, &event.Rule); err != nil {
			return nil, Event{}, fmt.Errorf("unmarshal rule: %w", err)
		}
	}
	if v, ok := raw["tags"]; ok {
		if err := json.Unmarshal(v, &event.Tags); err != nil {
			return nil, Event{}, fmt.Errorf("unmarshal tags: %w", err)
		}
	}
	if v, ok := raw["output_fields"]; ok {
		if err := json.Unmarshal(v, &event.OutputFields); err != nil {
			return nil, Event{}, fmt.Errorf("unmarshal output_fields: %w", err)
		}
	}

	return raw, event, nil
}

func (p *Proxy) shouldDrop(event Event) bool {
	if v, ok := event.OutputFields["container.image.repository"]; ok {
		if repo, ok := v.(string); ok && slices.Contains(p.ignoredImageRepositories, repo) {
			return true
		}
	}

	nsI, ok := event.OutputFields["k8s.ns.name"]
	if !ok {
		return false
	}
	ns, ok := nsI.(string)
	if !ok {
		return false
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

func stripAikidoTags(raw map[string]json.RawMessage, tags []string) (json.RawMessage, error) {
	filtered := make([]string, 0, len(tags))
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "aikido:") {
			filtered = append(filtered, tag)
		}
	}

	sanitizedTags, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	raw["tags"] = sanitizedTags

	return json.Marshal(raw)
}

// secretFields are the output_fields carrying user-controlled data where secrets
// realistically appear. Other fields are structural (names, namespaces, images)
// and are left unscanned to keep per-event redaction cost bounded.
var secretFields = []string{"proc.cmdline", "proc.args", "proc.exeline", "proc.env", "evt.args"}

func redactSecrets(raw map[string]json.RawMessage, redactor *Redactor) error {
	if err := redactOutputString(raw, redactor); err != nil {
		return err
	}
	return redactOutputFields(raw, redactor)
}

func redactOutputString(raw map[string]json.RawMessage, redactor *Redactor) error {
	v, ok := raw["output"]
	if !ok {
		return nil
	}
	var output string
	if err := json.Unmarshal(v, &output); err != nil {
		return nil
	}
	marshaled, err := json.Marshal(redactor.RedactText(output))
	if err != nil {
		return fmt.Errorf("marshal redacted output: %w", err)
	}
	raw["output"] = marshaled
	return nil
}

func redactOutputFields(raw map[string]json.RawMessage, redactor *Redactor) error {
	v, ok := raw["output_fields"]
	if !ok {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(v, &fields); err != nil {
		return nil
	}

	redactedAny := false
	for _, key := range secretFields {
		fieldValue, ok := fields[key]
		if !ok {
			continue
		}
		stringValue, ok := fieldValue.(string)
		if !ok {
			continue
		}
		fields[key] = redactor.RedactText(stringValue)
		redactedAny = true
	}
	if !redactedAny {
		return nil
	}

	marshaled, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("marshal redacted output_fields: %w", err)
	}
	raw["output_fields"] = marshaled
	return nil
}

func hasAikidoTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "aikido:") {
			return true
		}
	}
	return false
}
