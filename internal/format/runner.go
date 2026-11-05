package format

import (
	"bytes"
	"encoding/json"

	summerwindv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FormatRunner drops the GitHub Actions runner registration token that legacy ARC
// stores in a Runner's status. It is a short-lived bearer credential that can
// register a self-hosted runner (and thereby intercept workflow jobs and their
// secrets) during its validity window, and the agent has no reason to collect it.
// The rest of the status is enough to reason about the runner.
//
// A status that cannot be parsed is dropped whole: forwarding bytes the token could
// not be removed from would defeat the point.
func FormatRunner(obj client.Object) client.Object {
	runner, ok := obj.(*summerwindv1alpha1.Runner)
	if !ok || len(runner.Status.Raw) == 0 {
		return obj
	}

	// UseNumber keeps integers above 2^53 exact through the re-encode.
	decoder := json.NewDecoder(bytes.NewReader(runner.Status.Raw))
	decoder.UseNumber()

	var status map[string]any
	if err := decoder.Decode(&status); err != nil {
		runner.Status.Raw = nil
		return runner
	}

	if registration, ok := status["registration"].(map[string]any); ok {
		delete(registration, "token")
	}

	// Always forward the re-encoded map, never the served bytes: a duplicate key keeps
	// only its last value when parsed, so the served bytes could still hold a token.
	scrubbed, err := json.Marshal(status)
	if err != nil {
		runner.Status.Raw = nil
		return runner
	}
	runner.Status.Raw = scrubbed

	return runner
}
