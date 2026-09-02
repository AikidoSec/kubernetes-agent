package format

import (
	summerwindv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FormatRunner drops the GitHub Actions runner registration token that legacy ARC
// stores in a Runner's status. It is a short-lived bearer credential that can
// register a self-hosted runner (and thereby intercept workflow jobs and their
// secrets) during its validity window, and the agent has no reason to collect it.
// The rest of the status is enough to reason about the runner.
func FormatRunner(obj client.Object) client.Object {
	runner, ok := obj.(*summerwindv1alpha1.Runner)
	if !ok {
		return obj
	}

	runner.Status.Registration.Token = ""

	return runner
}
