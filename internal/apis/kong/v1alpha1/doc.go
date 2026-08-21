// Package v1alpha1 mirrors the Kong KongRoute and KongService types the agent watches,
// copied verbatim from kubernetes-configuration v2.0.1 (api/configuration/v1alpha1,
// api/common/v1alpha1, api/konnect/v1alpha2) and sdk-konnect-go v0.9.1
// (models/components). Why they are mirrored rather than imported:
// ../../THIRD_PARTY_NOTICES.md.
//
// One deliberate behaviour change: the SDK enums are plain string and int64 here.
// Upstream generates an UnmarshalJSON on each that rejects any value outside the
// pinned SDK's list, so a new Kong protocol value fails the decode of the whole
// KongRoute and the resource stops being reported until the SDK is bumped. The agent
// only forwards these values. Output stays byte-identical for values upstream
// accepted; the mirror additionally forwards ones it did not.
//
// To bump: diff against the upstream sources, port the changes, then regenerate
// testdata/ from the new upstream types, never from the mirror, or the golden stops
// being independent evidence. Then re-run the payload tests.
package v1alpha1
