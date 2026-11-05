package format_test

import (
	"encoding/json"
	"strings"
	"testing"

	summerwindv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/format"
	"k8s.io/apimachinery/pkg/runtime"
)

const registrationToken = "ATOKEN-secret-value"

func runnerWithStatus(status string) *summerwindv1alpha1.Runner {
	runner := &summerwindv1alpha1.Runner{}
	if status != "" {
		runner.Status = runtime.RawExtension{Raw: []byte(status)}
	}
	return runner
}

func decodeStatus(t *testing.T, runner *summerwindv1alpha1.Runner) map[string]any {
	t.Helper()
	var status map[string]any
	if err := json.Unmarshal(runner.Status.Raw, &status); err != nil {
		t.Fatalf("decoding formatted status: %v", err)
	}
	return status
}

// TestFormatRunnerStripsRegistrationToken guards against leaking the short-lived
// runner registration bearer token to the assets API.
func TestFormatRunnerStripsRegistrationToken(t *testing.T) {
	runner := runnerWithStatus(`{"ready":true,"registration":{"repository":"octo/repo",` +
		`"token":"` + registrationToken + `","expiresAt":"2026-10-22T10:00:00Z"}}`)

	got := format.FormatRunner(runner).(*summerwindv1alpha1.Runner)

	registration, ok := decodeStatus(t, got)["registration"].(map[string]any)
	if !ok {
		t.Fatalf("registration was dropped: %s", got.Status.Raw)
	}
	if _, found := registration["token"]; found {
		t.Errorf("registration token not stripped: %s", got.Status.Raw)
	}
	if registration["repository"] != "octo/repo" {
		t.Errorf("non-secret registration field was dropped: %s", got.Status.Raw)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling formatted runner: %v", err)
	}
	if strings.Contains(string(payload), registrationToken) {
		t.Errorf("token value present in emitted payload: %s", payload)
	}
}

// The status is re-encoded to remove the token, so fields the agent knows nothing about
// and integers too large for float64 must come through unchanged.
func TestFormatRunnerPreservesTheRestOfTheStatus(t *testing.T) {
	runner := runnerWithStatus(`{"phase":"Running","futureField":{"nested":[1,2]},` +
		`"bigCounter":9007199254740993,"registration":{"token":"` + registrationToken + `"}}`)

	got := format.FormatRunner(runner).(*summerwindv1alpha1.Runner)

	raw := string(got.Status.Raw)
	for _, want := range []string{`"phase":"Running"`, `"futureField":{"nested":[1,2]}`, `"bigCounter":9007199254740993`} {
		if !strings.Contains(raw, want) {
			t.Errorf("status lost %s: %s", want, raw)
		}
	}
	if strings.Contains(raw, registrationToken) {
		t.Errorf("registration token not stripped: %s", raw)
	}
}

// A status without a token keeps every field. It is re-encoded too, so its keys come
// back sorted.
func TestFormatRunnerKeepsStatusWithoutToken(t *testing.T) {
	for name, testCase := range map[string]struct{ status, want string }{
		"no registration": {
			status: `{"ready":true,"phase":"Running"}`,
			want:   `{"phase":"Running","ready":true}`,
		},
		"registration not object": {
			status: `{"registration":"pending","phase":"Pending"}`,
			want:   `{"phase":"Pending","registration":"pending"}`,
		},
		"registration no token": {
			status: `{"registration":{"repository":"octo/repo","expiresAt":"2026-10-22T10:00:00Z"}}`,
			want:   `{"registration":{"expiresAt":"2026-10-22T10:00:00Z","repository":"octo/repo"}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := format.FormatRunner(runnerWithStatus(testCase.status)).(*summerwindv1alpha1.Runner)
			if string(got.Status.Raw) != testCase.want {
				t.Errorf("status changed\nwant: %s\ngot:  %s", testCase.want, got.Status.Raw)
			}
		})
	}
}

// A duplicate key keeps only its last value when parsed, so forwarding the served bytes
// whenever the parsed status looks token-free would leak a token behind an earlier one.
func TestFormatRunnerStripsTokenBehindDuplicateKeys(t *testing.T) {
	for name, status := range map[string]string{
		"later registration is not an object": `{"registration":{"token":"` + registrationToken + `"},"registration":"pending"}`,
		"later registration has no token":     `{"registration":{"token":"` + registrationToken + `"},"registration":{"repository":"octo/repo"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := format.FormatRunner(runnerWithStatus(status)).(*summerwindv1alpha1.Runner)
			if strings.Contains(string(got.Status.Raw), registrationToken) {
				t.Errorf("registration token forwarded: %s", got.Status.Raw)
			}
		})
	}
}

// Anything after the first JSON value is ignored when parsing, so it must not be
// forwarded either.
func TestFormatRunnerDropsTrailingData(t *testing.T) {
	status := `{"ready":true} {"registration":{"token":"` + registrationToken + `"}}`

	got := format.FormatRunner(runnerWithStatus(status)).(*summerwindv1alpha1.Runner)

	if string(got.Status.Raw) != `{"ready":true}` {
		t.Errorf("trailing data forwarded: %s", got.Status.Raw)
	}
}

func TestFormatRunnerWithoutStatus(t *testing.T) {
	got := format.FormatRunner(runnerWithStatus("")).(*summerwindv1alpha1.Runner)
	if got.Status.Raw != nil {
		t.Errorf("empty status became %s", got.Status.Raw)
	}
}

// A status the token cannot be checked for must never be forwarded.
func TestFormatRunnerDropsUnparseableStatus(t *testing.T) {
	for name, status := range map[string]string{
		"not an object": `["` + registrationToken + `"]`,
		"truncated":     `{"registration":{"token":"` + registrationToken + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			got := format.FormatRunner(runnerWithStatus(status)).(*summerwindv1alpha1.Runner)
			if got.Status.Raw != nil {
				t.Errorf("unparseable status was forwarded: %s", got.Status.Raw)
			}
		})
	}
}

// TestFormatObjectDispatchesRunner covers the GVK-string wiring the controller relies on.
func TestFormatObjectDispatchesRunner(t *testing.T) {
	runner := runnerWithStatus(`{"registration":{"token":"` + registrationToken + `"}}`)

	formatted := format.FormatObject(runner, "actions.summerwind.dev/v1alpha1, Kind=Runner", nil)

	got := formatted.(*summerwindv1alpha1.Runner)
	if strings.Contains(string(got.Status.Raw), registrationToken) {
		t.Errorf("FormatObject did not route Runner through FormatRunner: %s", got.Status.Raw)
	}
}
