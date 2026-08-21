// Package v1alpha1 mirrors the KEDA ScaledObject and ScaledJob types the agent
// watches, copied verbatim from KEDA v2.20.0 (apis/keda/v1alpha1, upstream file names
// preserved). Why they are mirrored rather than imported:
// ../../THIRD_PARTY_NOTICES.md.
//
// To bump: diff against the upstream sources, port the changes, then regenerate
// testdata/ from the new upstream types, never from the mirror, or the golden stops
// being independent evidence. Then re-run the payload tests.
package v1alpha1
