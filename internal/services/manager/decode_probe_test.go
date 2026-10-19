package manager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ephemeralRunnerGVK = schema.GroupVersionKind{Group: "actions.github.com", Version: "v1alpha1", Kind: "EphemeralRunner"}

// newProbeClient points a real controller-runtime client at a stub API server so the
// probe exercises the same decode path the informer's initial LIST takes.
func newProbeClient(t *testing.T, handler http.HandlerFunc) (client.Reader, *runtime.Scheme) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	scheme := runtime.NewScheme()
	if err := ghv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering arc github types: %v", err)
	}

	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{ephemeralRunnerGVK.GroupVersion()})
	mapper.Add(ephemeralRunnerGVK, meta.RESTScopeNamespace)

	// QPS -1 disables client-go's default 5/s limiter, so paging tests measure the
	// probe's budget rather than the rate limiter.
	config := &rest.Config{Host: server.URL, QPS: -1}
	reader, err := client.New(config, client.Options{Scheme: scheme, Mapper: mapper})
	if err != nil {
		t.Fatalf("building client: %v", err)
	}
	return reader, scheme
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("writing response: %v", err)
	}
}

func listBody(continueToken, items string) string {
	return `{"apiVersion":"actions.github.com/v1alpha1","kind":"EphemeralRunnerList",` +
		`"metadata":{"continue":"` + continueToken + `"},"items":[` + items + `]}`
}

func TestProbeTypedDecodeAcceptsServedPayload(t *testing.T) {
	reader, scheme := newProbeClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, listBody("", `{"metadata":{"name":"runner-1"},"status":{"failures":{"a":true}}}`))
	})

	if err := probeTypedDecode(context.Background(), reader, scheme, ephemeralRunnerGVK); err != nil {
		t.Errorf("probe rejected a decodable payload: %v", err)
	}
}

func TestProbeTypedDecodeFlagsDriftedPayload(t *testing.T) {
	reader, scheme := newProbeClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, listBody("", `{"metadata":{"name":"runner-1"},"status":{"runnerId":"not-a-number"}}`))
	})

	err := probeTypedDecode(context.Background(), reader, scheme, ephemeralRunnerGVK)

	var mismatch *schemaMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want *schemaMismatchError, got %T: %v", err, err)
	}
}

// The caveat that rules out a cheap single-item probe: page one can decode while the
// page carrying the drifted field does not.
func TestProbeTypedDecodeReadsEveryPage(t *testing.T) {
	var requests int
	reader, scheme := newProbeClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			writeJSON(t, w, http.StatusOK, listBody("page-2", `{"metadata":{"name":"runner-1"},"status":{"runnerId":1}}`))
			return
		}
		writeJSON(t, w, http.StatusOK, listBody("", `{"metadata":{"name":"runner-2"},"status":{"runnerId":"not-a-number"}}`))
	})

	err := probeTypedDecode(context.Background(), reader, scheme, ephemeralRunnerGVK)

	var mismatch *schemaMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want *schemaMismatchError, got %T: %v", err, err)
	}
	if requests != 2 {
		t.Errorf("made %d requests, want 2", requests)
	}
}

// An API-side failure must not permanently disable a watcher.
func TestProbeTypedDecodeToleratesAPIFailure(t *testing.T) {
	reader, scheme := newProbeClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden,
			`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}`)
	})

	err := probeTypedDecode(context.Background(), reader, scheme, ephemeralRunnerGVK)
	if err == nil {
		t.Fatal("want an error for a forbidden list")
	}

	var mismatch *schemaMismatchError
	if errors.As(err, &mismatch) {
		t.Errorf("forbidden list classified as a schema mismatch: %v", err)
	}
}

// The probe runs before mgr.Start and the REST config carries no timeout, so a LIST
// that is accepted and never answered must not hang startup.
func TestProbeTypedDecodeBoundsAStalledList(t *testing.T) {
	released := make(chan struct{})
	reader, scheme := newProbeClient(t, func(http.ResponseWriter, *http.Request) {
		<-released
	})
	// Registered after newProbeClient so this runs before its server.Close, which
	// would otherwise block on the stalled handler.
	t.Cleanup(func() { close(released) })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- probeTypedDecode(ctx, reader, scheme, ephemeralRunnerGVK) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want an error for a stalled list")
		}
		var mismatch *schemaMismatchError
		if errors.As(err, &mismatch) {
			t.Errorf("stalled list classified as a schema mismatch: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("probe did not return; it is not bounded")
	}
}

// Paging must not run unbounded against a server that always returns a continue token.
func TestProbeTypedDecodeBoundsEndlessPaging(t *testing.T) {
	var requests int
	reader, scheme := newProbeClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, w, http.StatusOK, listBody("more", `{"metadata":{"name":"runner-1"},"status":{}}`))
	})

	err := probeTypedDecode(context.Background(), reader, scheme, ephemeralRunnerGVK)
	if err == nil {
		t.Fatal("want an error once the page budget is spent")
	}

	var mismatch *schemaMismatchError
	if errors.As(err, &mismatch) {
		t.Errorf("page budget exhaustion classified as a schema mismatch: %v", err)
	}
	if requests != decodeProbeMaxPages {
		t.Errorf("made %d requests, want %d", requests, decodeProbeMaxPages)
	}
}

func TestProbeTypedDecodeToleratesUnreachableAPI(t *testing.T) {
	reader, scheme := newProbeClient(t, func(http.ResponseWriter, *http.Request) {})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := probeTypedDecode(ctx, reader, scheme, ephemeralRunnerGVK)
	if err == nil {
		t.Fatal("want an error for a cancelled context")
	}

	var mismatch *schemaMismatchError
	if errors.As(err, &mismatch) {
		t.Errorf("cancelled context classified as a schema mismatch: %v", err)
	}
}
