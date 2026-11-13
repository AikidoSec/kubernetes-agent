package falco

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeClient struct {
	mu   sync.Mutex
	sent []string
}

func (f *fakeClient) SendContext(_ context.Context, e any) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, string(b))
	return nil
}
func (f *fakeClient) SetAPIToken(string)          {}
func (f *fakeClient) Close(context.Context) error { return nil }

func (f *fakeClient) payloads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

const routeTag = "aikido:threat-detection"

func newHandlerProxy(redactor *Redactor, route Route) *Proxy {
	p := newTestProxy(nil, nil, nil)
	p.redactor = redactor
	p.redactSlots = make(chan struct{}, 1)
	route.Tag = routeTag
	p.routes = []Route{route}
	return p
}

func post(p *Proxy, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	p.handleRequest(rec, httptest.NewRequest(http.MethodPost, "/detection", strings.NewReader(body)))
	return rec
}

func secretEvent(tags string) string {
	return `{"rule":"r","tags":` + tags + `,"output":"ran with ` + testSecret + `",` +
		`"output_fields":{"proc.pcmdline":"bash -c ` + testSecret + `","proc.cwd":"/tmp/` + testSecret + `","proc.name":"bash"}}`
}

func TestHandleRequestRedactsEverywhereBeforeForwarding(t *testing.T) {
	client := &fakeClient{}
	p := newHandlerProxy(newTestRedactor(t), Route{Client: client})

	rec := post(p, secretEvent(`["network","`+routeTag+`"]`))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	got := client.payloads()
	if len(got) != 1 {
		t.Fatalf("forwarded %d events, want 1", len(got))
	}
	if strings.Contains(got[0], testSecret) {
		t.Errorf("forwarded payload still contains plaintext secret: %s", got[0])
	}
	if !strings.Contains(got[0], "redacted-") {
		t.Errorf("expected redaction token in payload: %s", got[0])
	}
	if strings.Contains(got[0], routeTag) {
		t.Errorf("aikido tag was not stripped: %s", got[0])
	}
	if !strings.Contains(got[0], `"proc.name":"bash"`) {
		t.Errorf("non-secret field was altered: %s", got[0])
	}
}

func TestHandleRequestSkipsScanForUnroutableEvents(t *testing.T) {
	tests := []struct {
		name  string
		route Route
		tags  string
	}{
		{"no routing tag", Route{}, `["network"]`},
		{"route disabled", Route{IsEnabled: func() bool { return false }}, `["` + routeTag + `"]`},
		{"rule skipped", Route{ShouldSkip: func(Event) bool { return true }}, `["` + routeTag + `"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeClient{}
			tt.route.Client = client
			// Occupy the only scan slot and cancel the request context: if the
			// handler tried to scan it would answer 503 instead of 202.
			p := newHandlerProxy(newTestRedactor(t), tt.route)
			p.redactSlots <- struct{}{}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			req := httptest.NewRequest(http.MethodPost, "/detection", strings.NewReader(secretEvent(tt.tags))).WithContext(ctx)
			rec := httptest.NewRecorder()
			p.handleRequest(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d (scan must not be attempted)", rec.Code, http.StatusAccepted)
			}
			if n := len(client.payloads()); n != 0 {
				t.Errorf("forwarded %d events, want 0", n)
			}
		})
	}
}

func TestHandleRequestDropsEventWhenRedactionFails(t *testing.T) {
	client := &fakeClient{}
	p := newHandlerProxy(nil, Route{Client: client}) // nil redactor => redactSecrets errors

	rec := post(p, secretEvent(`["`+routeTag+`"]`))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if n := len(client.payloads()); n != 0 {
		t.Errorf("forwarded %d events, want 0 (fail closed)", n)
	}
}

func TestHandleRequestReturns503WhenCancelledWaitingForSlot(t *testing.T) {
	client := &fakeClient{}
	p := newHandlerProxy(newTestRedactor(t), Route{Client: client})
	p.redactSlots <- struct{}{} // occupy the only slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/detection", strings.NewReader(secretEvent(`["`+routeTag+`"]`))).WithContext(ctx)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if n := len(client.payloads()); n != 0 {
		t.Errorf("forwarded %d events, want 0", n)
	}
}
