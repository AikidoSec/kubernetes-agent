// Package v1alpha1 mirrors the legacy GitHub ARC (community, "summerwind") Runner
// type the agent watches, copied verbatim from actions-runner-controller
// gha-runner-scale-set-0.14.2 (apis/actions.summerwind.net/v1alpha1/runner_types.go)
// and extracted by walking the Runner type closure. Runner is the only kind in this
// group that directly owns a Pod. Why it is mirrored rather than imported:
// ../../../THIRD_PARTY_NOTICES.md.
//
// The group constant is actions.summerwind.dev even though the upstream source
// directory is named actions.summerwind.net; the CRD in a cluster uses .dev.
//
// Upstream's Validate methods and admission webhooks are deliberately not mirrored —
// the agent only serializes the object, never validates it — so the errors, fmt and
// validation/field imports upstream needs for them are dropped here.
//
// To bump: re-extract rather than hand-editing, regenerate testdata/ from the new
// upstream types (never from the mirror, or the golden stops being independent
// evidence), then re-run the payload tests.
package v1alpha1
