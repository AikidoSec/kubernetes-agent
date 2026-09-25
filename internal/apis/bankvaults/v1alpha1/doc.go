// Package v1alpha1 mirrors the Bank-Vaults vault-operator Vault type the agent
// watches, copied verbatim from bank-vaults/vault-operator v1.24.0
// (pkg/apis/vault/v1alpha1). Vault is the only kind the operator defines, and it is
// the root owner of every Pod the operator runs: it owns the Vault StatefulSet and
// the vault-configurer Deployment, which in turn own the Pods. Why it is mirrored
// rather than imported: ../../THIRD_PARTY_NOTICES.md.
//
// Upstream's spec accessors (GetVaultImage, ConfigJSON, UnsealConfig.ToArgs and the
// rest) are deliberately not mirrored — the agent only serializes the object, never
// reads a field of its spec — so the semver, mergo, cast and docker-ref imports
// upstream needs for them are dropped here. VaultSpec.Config and
// VaultSpec.ExternalConfig keep their upstream apiextensions v1beta1 JSON type: it
// is a k8s.io API type already in the build, and its custom marshalling is what
// keeps the raw Vault configuration byte-identical on the wire.
//
// To bump: re-extract rather than hand-editing, regenerate testdata/ from the new
// upstream types (never from the mirror, or the golden stops being independent
// evidence), then re-run the payload tests.
package v1alpha1
