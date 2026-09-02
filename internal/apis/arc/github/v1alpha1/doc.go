// Package v1alpha1 mirrors the GitHub ARC (gha-runner-scale-set) EphemeralRunner
// and AutoscalingListener types the agent watches, copied verbatim from
// actions-runner-controller gha-runner-scale-set-0.14.2 (apis/actions.github.com/v1alpha1)
// and extracted by walking each kind's type closure, so the set is exactly what
// EphemeralRunner and AutoscalingListener reach. These are the only kinds in this
// group that directly own a Pod. Why they are mirrored rather than imported:
// ../../../THIRD_PARTY_NOTICES.md.
//
// The shared spec types (TLSConfig, ProxyConfig, VaultConfig, MetricsConfig,
// ResourceMeta, and their nested types) live in upstream's common.go and
// autoscalingrunnerset_types.go; only the subset reached by the two mirrored kinds
// is copied here. VaultConfig.Type is upstream's vault.VaultType, a string-underlying
// type mirrored locally as VaultType to avoid importing the upstream module.
//
// Registration deliberately uses this repo's runtime.NewSchemeBuilder(addKnownTypes)
// convention rather than upstream's scheme.Builder + per-file init(), so no kind
// registers itself as a side effect of import.
//
// To bump: re-extract rather than hand-editing, regenerate testdata/ from the new
// upstream types (never from the mirror, or the golden stops being independent
// evidence), then re-run the payload tests.
package v1alpha1
