package format_test

import (
	"encoding/json"
	"strings"
	"testing"

	summerwindv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/format"
)

// TestFormatRunnerStripsRegistrationToken guards against leaking the short-lived
// runner registration bearer token to the assets API.
func TestFormatRunnerStripsRegistrationToken(t *testing.T) {
	runner := &summerwindv1alpha1.Runner{}
	runner.Status.Registration.Token = "ATOKEN-secret-value"
	runner.Status.Registration.Repository = "octo/repo"

	formatted := format.FormatRunner(runner)

	got := formatted.(*summerwindv1alpha1.Runner)
	if got.Status.Registration.Token != "" {
		t.Errorf("registration token not stripped: got %q", got.Status.Registration.Token)
	}
	if got.Status.Registration.Repository != "octo/repo" {
		t.Errorf("non-secret status field was dropped: repository = %q", got.Status.Registration.Repository)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling formatted runner: %v", err)
	}
	if strings.Contains(string(payload), "ATOKEN-secret-value") {
		t.Errorf("token value present in emitted payload: %s", payload)
	}
}

// TestFormatObjectDispatchesRunner covers the GVK-string wiring the controller relies on.
func TestFormatObjectDispatchesRunner(t *testing.T) {
	runner := &summerwindv1alpha1.Runner{}
	runner.Status.Registration.Token = "ATOKEN-secret-value"

	formatted := format.FormatObject(runner, "actions.summerwind.dev/v1alpha1, Kind=Runner", nil)

	if got := formatted.(*summerwindv1alpha1.Runner); got.Status.Registration.Token != "" {
		t.Errorf("FormatObject did not route Runner through FormatRunner: token = %q", got.Status.Registration.Token)
	}
}
