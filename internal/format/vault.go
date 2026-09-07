package format

import (
	vaultv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/bankvaults/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FormatVault drops the two unseal credentials that the Bank-Vaults vault-operator
// accepts inline in a Vault spec: the token used to authenticate against a remote
// Vault, and the PIN that unlocks an HSM slot. Both grant access to the unseal keys
// of the Vault cluster, and the agent has no reason to collect them. The rest of the
// unseal configuration only names where the keys live, which is what makes the
// object worth reasoning about.
func FormatVault(obj client.Object) client.Object {
	vault, ok := obj.(*vaultv1alpha1.Vault)
	if !ok {
		return obj
	}

	if vault.Spec.UnsealConfig.Vault != nil {
		vault.Spec.UnsealConfig.Vault.Token = ""
	}
	if vault.Spec.UnsealConfig.HSM != nil {
		vault.Spec.UnsealConfig.HSM.Pin = ""
	}

	return vault
}
