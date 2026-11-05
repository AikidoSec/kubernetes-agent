// Package v1alpha1 holds stubs for the legacy GitHub ARC (summerwind) kinds the agent
// watches. Spec and status stay as the bytes the API server served, so every field
// survives whatever CRD version a cluster runs, and an upstream schema change cannot
// fail the decode. Why: ../../../README.md.
//
// zz_generated.deepcopy.go is generated:
//
//	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0 object paths=.
//
// +kubebuilder:object:generate=true
package v1alpha1
