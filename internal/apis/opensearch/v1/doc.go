// Package v1 mirrors the OpenSearch Kubernetes operator's OpenSearchCluster type,
// copied verbatim from opensearch-k8s-operator v2.8.0 (opensearch-operator/api/v1)
// and extracted by walking the kind's type closure, so the set is exactly what
// OpenSearchCluster reaches. It is the only kind in this group that owns a Pod
// directly: the operator gives the pre-initialisation bootstrap pod a controller
// reference to the cluster CR, while every other pod it creates is owned by a
// StatefulSet, Deployment or Job. Why the types are mirrored rather than imported:
// ../../THIRD_PARTY_NOTICES.md.
//
// Upstream declares TlsSecret and OpensearchClusterSelector in the same package;
// neither is reachable from OpenSearchCluster, so neither is copied. The PhasePending
// and PhaseRunning constants and the OpenSearchHealth values are likewise dropped —
// the closure walk yields types only, and the agent never compares against them.
//
// Registration deliberately uses this repo's runtime.NewSchemeBuilder(addKnownTypes)
// convention rather than upstream's scheme.Builder + per-file init(), so no kind
// registers itself as a side effect of import.
//
// To bump: re-extract rather than hand-editing, regenerate testdata/ from the new
// upstream types (never from the mirror, or the golden stops being independent
// evidence), then re-run the payload tests.
package v1
