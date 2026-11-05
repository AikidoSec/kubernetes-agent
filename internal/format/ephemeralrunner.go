package format

import (
	"bytes"
	"encoding/json"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FormatEphemeralRunner drops the just-in-time runner configuration that ARC up to
// gha-runner-scale-set-0.12.1 stores in an EphemeralRunner's status. It is an encoded
// runner registration credential, and the agent has no reason to collect it.
//
// A status that cannot be parsed is dropped whole: forwarding bytes the credential could
// not be removed from would defeat the point.
func FormatEphemeralRunner(obj client.Object) client.Object {
	ephemeralRunner, ok := obj.(*ghv1alpha1.EphemeralRunner)
	if !ok || len(ephemeralRunner.Status.Raw) == 0 {
		return obj
	}

	// UseNumber keeps integers above 2^53 exact through the re-encode.
	decoder := json.NewDecoder(bytes.NewReader(ephemeralRunner.Status.Raw))
	decoder.UseNumber()

	var status map[string]any
	if err := decoder.Decode(&status); err != nil {
		ephemeralRunner.Status.Raw = nil
		return ephemeralRunner
	}

	delete(status, "runnerJITConfig")

	// Always forward the re-encoded map, never the served bytes: a duplicate key keeps
	// only its last value when parsed, so the served bytes could still hold the config.
	scrubbed, err := json.Marshal(status)
	if err != nil {
		ephemeralRunner.Status.Raw = nil
		return ephemeralRunner
	}
	ephemeralRunner.Status.Raw = scrubbed

	return ephemeralRunner
}
