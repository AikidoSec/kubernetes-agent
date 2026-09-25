# Third-party notices

The packages under `internal/apis/` contain type declarations copied from upstream
projects rather than imported from them. Each package's `doc.go` explains why, what was
left out, and how to re-sync on a version bump. This file records provenance and
licensing for the copied code.

The agent watches these CRDs but only ever serializes them, never reads a field of
their specs. Importing the upstream modules pulled roughly 50 modules into the build
that the agent does not use, and coupled its Kubernetes library versions to whatever
each project happened to require. Mirroring the types removes both problems while
keeping the emitted JSON byte-identical, which is checked by the payload tests in each
package against golden files generated from the upstream types.

| Package | Upstream | Version | Licence |
| --- | --- | --- | --- |
| `traefik/v1alpha1` | github.com/traefik/traefik | v3.6.25 | MIT |
| `keda/v1alpha1` | github.com/kedacore/keda | v2.20.0 | Apache-2.0 |
| `kong/v1alpha1` | github.com/kong/kubernetes-configuration | v2.0.1 | Apache-2.0 |
| `kong/v1alpha1` | github.com/Kong/sdk-konnect-go | v0.9.1 | Apache-2.0 |
| `rollouts/v1alpha1` | github.com/argoproj/argo-rollouts | v1.9.0 | Apache-2.0 |
| `arc/github/v1alpha1` | github.com/actions/actions-runner-controller | gha-runner-scale-set-0.14.2 | Apache-2.0 |
| `arc/summerwind/v1alpha1` | github.com/actions/actions-runner-controller | gha-runner-scale-set-0.14.2 | Apache-2.0 |
| `bankvaults/v1alpha1` | github.com/bank-vaults/vault-operator | v1.24.0 | Apache-2.0 |

Files copied from the Apache-2.0 projects retain their upstream copyright headers where
upstream carried them, as that licence requires. Traefik distributes under MIT with a
single repository-level `LICENSE.md` and no per-file headers; its notice is reproduced
below.

## github.com/traefik/traefik

```
The MIT License (MIT)

Copyright (c) 2016-2020 Containous SAS; 2020-2025 Traefik Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Apache-2.0 projects

KEDA, kubernetes-configuration, sdk-konnect-go, argo-rollouts,
actions-runner-controller and vault-operator are all distributed
under the Apache License, Version 2.0, available at
<http://www.apache.org/licenses/LICENSE-2.0>. None of the copied files were modified in
ways that change their behaviour; the deviations that do exist are listed in each
package's `doc.go`.
