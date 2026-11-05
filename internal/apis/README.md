# Vendor CRD stubs

The packages under `internal/apis/` hold hand-written stubs for the third-party
CRD kinds the agent watches. None of them contain code copied from upstream.

| Package | Kinds | Upstream project |
| --- | --- | --- |
| `traefik/v1alpha1` | IngressRoute | traefik/traefik |
| `keda/v1alpha1` | ScaledObject, ScaledJob | kedacore/keda |
| `kong/v1alpha1` | KongRoute, KongService | Kong/kubernetes-configuration |
| `rollouts/v1alpha1` | Rollout | argoproj/argo-rollouts |
| `arc/github/v1alpha1` | EphemeralRunner, AutoscalingListener | actions/actions-runner-controller |
| `arc/summerwind/v1alpha1` | Runner | actions/actions-runner-controller |

## Why stubs

The agent decodes these objects only to cache them, filter them, and send
them to the backend. It reads `metadata` but never a field of `spec` or
`status`. The exceptions are the scrubbers in `internal/format`, which remove
credentials from a status (see [Secrets](#secrets)).

Each stub therefore declares typed `TypeMeta` and `ObjectMeta`, which the
cache, predicates and namespace filter need, and keeps `spec` and `status` as
`runtime.RawExtension`: the bytes the API server served. As a result:

- Fields every CRD version adds reach the backend instead of being dropped by
  a Go struct that does not declare them.
- A field whose type differs between versions cannot fail the decode. A
  single undecodable item fails an informer's whole LIST, and the cache never
  syncs.
- Fields the cluster did not send are not invented in the payload.
- There is no upstream version to pin, re-sync, or check for drift.

ArgoCD's `Application` uses a similar layout, in
`internal/controllers/argoproj/argocd.go`, though without `omitzero` and with
a hand-written deepcopy.

## Secrets

Forwarding every field is also the risk. A Go struct that did not declare a
field dropped it, which happened to keep secret values out of the payload.
With raw `spec` and `status`, any field holding a secret value, in any CRD
version a cluster runs, reaches the backend unless a scrubber removes it.

| Kind | Field | Versions | Scrubber |
| --- | --- | --- | --- |
| Runner | `status.registration.token` | summerwind ARC | `format.FormatRunner` |
| EphemeralRunner | `status.runnerJITConfig` | gha-runner-scale-set 0.2.0 to 0.12.1 | `format.FormatEphemeralRunner` |

A scrubber always forwards the status it re-encoded from the parsed fields,
never the bytes the API server served, so a duplicate key or trailing data
cannot carry a secret through. A status it cannot parse is dropped whole.

When adding a kind or supporting a new upstream version, check the CRD schema
of every version for fields that hold a secret value, not a reference to a
Secret, and add a scrubber to `format.FormatObject` for each.

## Adding a kind

1. Add the object and list types to the package's `types.go`, following the
   existing layout, and register both in `register.go`.
2. Regenerate the deepcopy functions from the package directory:

   ```sh
   go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0 object paths=.
   ```

3. Add the kind to the package's `types_test.go`. `stubtest.Run` checks
   registration, verbatim forwarding, and deep-copy independence.

If the agent ever needs to read a field, decode just that field from
`Spec.Raw` or `Status.Raw` into a small struct where it is used, rather than
declaring the upstream schema here.
