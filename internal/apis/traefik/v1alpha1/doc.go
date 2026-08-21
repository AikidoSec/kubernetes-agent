// Package v1alpha1 mirrors the Traefik IngressRoute types the agent watches, copied
// verbatim from traefik v3.6.25 (pkg/provider/kubernetes/crd/traefikio/v1alpha1).
// Why they are mirrored rather than imported: ../../THIRD_PARTY_NOTICES.md.
//
// To bump: diff against the upstream sources, port the changes, then regenerate
// testdata/ from the new upstream types, never from the mirror, or the golden stops
// being independent evidence. Then re-run the payload tests.
package v1alpha1
