package format_test

import (
	"encoding/json"
	"strings"
	"testing"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/format"
	"k8s.io/apimachinery/pkg/runtime"
)

const jitConfig = "eyJhbGciOi-encoded-jit-config"

func ephemeralRunnerWithStatus(status string) *ghv1alpha1.EphemeralRunner {
	ephemeralRunner := &ghv1alpha1.EphemeralRunner{}
	if status != "" {
		ephemeralRunner.Status = runtime.RawExtension{Raw: []byte(status)}
	}
	return ephemeralRunner
}

// TestFormatEphemeralRunnerStripsJITConfig guards against leaking the encoded runner
// registration credential ARC up to gha-runner-scale-set-0.12.1 keeps in status.
func TestFormatEphemeralRunnerStripsJITConfig(t *testing.T) {
	ephemeralRunner := ephemeralRunnerWithStatus(`{"phase":"Running","runnerId":42,"runnerName":"runner-a",` +
		`"runnerJITConfig":"` + jitConfig + `","failures":{"a":true,"b":"2024-12-12T10:40:00Z"},` +
		`"bigCounter":9007199254740993}`)

	got := format.FormatEphemeralRunner(ephemeralRunner).(*ghv1alpha1.EphemeralRunner)

	raw := string(got.Status.Raw)
	if strings.Contains(raw, jitConfig) || strings.Contains(raw, "runnerJITConfig") {
		t.Errorf("runnerJITConfig not stripped: %s", raw)
	}
	for _, want := range []string{`"phase":"Running"`, `"runnerId":42`, `"runnerName":"runner-a"`,
		`"failures":{"a":true,"b":"2024-12-12T10:40:00Z"}`, `"bigCounter":9007199254740993`} {
		if !strings.Contains(raw, want) {
			t.Errorf("status lost %s: %s", want, raw)
		}
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling formatted ephemeral runner: %v", err)
	}
	if strings.Contains(string(payload), jitConfig) {
		t.Errorf("JIT config present in emitted payload: %s", payload)
	}
}

// ARC from gha-runner-scale-set-0.13.0 no longer has the field. Such a status keeps
// every field; it is re-encoded too, so its keys come back sorted.
func TestFormatEphemeralRunnerKeepsStatusWithoutJITConfig(t *testing.T) {
	status := `{"phase":"Running","runnerName":"runner-a","runnerId":42}`
	want := `{"phase":"Running","runnerId":42,"runnerName":"runner-a"}`

	got := format.FormatEphemeralRunner(ephemeralRunnerWithStatus(status)).(*ghv1alpha1.EphemeralRunner)

	if string(got.Status.Raw) != want {
		t.Errorf("status changed\nwant: %s\ngot:  %s", want, got.Status.Raw)
	}
}

// A duplicate key keeps only its last value when parsed, so the served bytes can hold a
// JIT config the parsed status does not show.
func TestFormatEphemeralRunnerStripsJITConfigBehindDuplicateKeys(t *testing.T) {
	status := `{"runnerJITConfig":"` + jitConfig + `","phase":"Running","runnerJITConfig":"later"}`

	got := format.FormatEphemeralRunner(ephemeralRunnerWithStatus(status)).(*ghv1alpha1.EphemeralRunner)

	if string(got.Status.Raw) != `{"phase":"Running"}` {
		t.Errorf("want only phase forwarded, got: %s", got.Status.Raw)
	}
}

// Anything after the first JSON value is ignored when parsing, so it must not be
// forwarded either.
func TestFormatEphemeralRunnerDropsTrailingData(t *testing.T) {
	status := `{"phase":"Running"} {"runnerJITConfig":"` + jitConfig + `"}`

	got := format.FormatEphemeralRunner(ephemeralRunnerWithStatus(status)).(*ghv1alpha1.EphemeralRunner)

	if string(got.Status.Raw) != `{"phase":"Running"}` {
		t.Errorf("trailing data forwarded: %s", got.Status.Raw)
	}
}

func TestFormatEphemeralRunnerWithoutStatus(t *testing.T) {
	got := format.FormatEphemeralRunner(ephemeralRunnerWithStatus("")).(*ghv1alpha1.EphemeralRunner)
	if got.Status.Raw != nil {
		t.Errorf("empty status became %s", got.Status.Raw)
	}
}

// A status the credential cannot be checked for must never be forwarded.
func TestFormatEphemeralRunnerDropsUnparseableStatus(t *testing.T) {
	for name, status := range map[string]string{
		"not an object": `["` + jitConfig + `"]`,
		"truncated":     `{"runnerJITConfig":"` + jitConfig + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			got := format.FormatEphemeralRunner(ephemeralRunnerWithStatus(status)).(*ghv1alpha1.EphemeralRunner)
			if got.Status.Raw != nil {
				t.Errorf("unparseable status was forwarded: %s", got.Status.Raw)
			}
		})
	}
}

// TestFormatObjectDispatchesEphemeralRunner covers the GVK-string wiring the controller
// relies on.
func TestFormatObjectDispatchesEphemeralRunner(t *testing.T) {
	ephemeralRunner := ephemeralRunnerWithStatus(`{"runnerJITConfig":"` + jitConfig + `"}`)

	formatted := format.FormatObject(ephemeralRunner, "actions.github.com/v1alpha1, Kind=EphemeralRunner", nil)

	got := formatted.(*ghv1alpha1.EphemeralRunner)
	if strings.Contains(string(got.Status.Raw), jitConfig) {
		t.Errorf("FormatObject did not route EphemeralRunner through FormatEphemeralRunner: %s", got.Status.Raw)
	}
}
