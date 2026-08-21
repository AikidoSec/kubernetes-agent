// Package v1alpha1 mirrors the Argo Rollouts Rollout types the agent watches, copied
// verbatim from argo-rollouts v1.9.0 and extracted by walking the Rollout type
// closure, so the set is exactly what Rollout reaches. Why they are mirrored rather
// than imported: ../../THIRD_PARTY_NOTICES.md.
//
// Upstream's RolloutSpec.MarshalJSON is deliberately not mirrored. Its alternate
// branch strips template or selector and reorders every key by routing through
// DefaultUnstructuredConverter, but it is gated on two json:"-" flags that only
// argo-rollouts' own controller sets. They are always false after a decode, so the
// branch is unreachable here and plain struct marshalling is equivalent.
//
// To bump: re-extract rather than hand-editing, then regenerate testdata/ from the new
// upstream types, never from the mirror, or the golden stops being independent
// evidence. Then re-run the payload tests.
package v1alpha1
