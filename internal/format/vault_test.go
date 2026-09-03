package format_test

import (
	"encoding/json"
	"strings"
	"testing"

	vaultv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/bankvaults/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/format"
)

// TestFormatVaultStripsUnsealCredentials guards against leaking the credentials that
// unlock a Vault cluster's unseal keys to the assets API.
func TestFormatVaultStripsUnsealCredentials(t *testing.T) {
	vault := &vaultv1alpha1.Vault{}
	vault.Spec.UnsealConfig.Vault = &vaultv1alpha1.VaultUnsealConfig{
		Address:        "https://vault.example.com",
		UnsealKeysPath: "secret/vault-unseal-keys",
		Token:          "hvs.secret-value",
	}
	vault.Spec.UnsealConfig.HSM = &vaultv1alpha1.HSMUnsealConfig{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		Pin:        "1234-secret-pin",
	}

	formatted := format.FormatVault(vault)

	got := formatted.(*vaultv1alpha1.Vault)
	if got.Spec.UnsealConfig.Vault.Token != "" {
		t.Errorf("unseal vault token not stripped: got %q", got.Spec.UnsealConfig.Vault.Token)
	}
	if got.Spec.UnsealConfig.HSM.Pin != "" {
		t.Errorf("HSM pin not stripped: got %q", got.Spec.UnsealConfig.HSM.Pin)
	}
	if got.Spec.UnsealConfig.Vault.UnsealKeysPath != "secret/vault-unseal-keys" {
		t.Errorf("non-secret unseal field was dropped: unsealKeysPath = %q", got.Spec.UnsealConfig.Vault.UnsealKeysPath)
	}
	if got.Spec.UnsealConfig.HSM.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Errorf("non-secret unseal field was dropped: modulePath = %q", got.Spec.UnsealConfig.HSM.ModulePath)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling formatted vault: %v", err)
	}
	for _, secret := range []string{"hvs.secret-value", "1234-secret-pin"} {
		if strings.Contains(string(payload), secret) {
			t.Errorf("credential %q present in emitted payload: %s", secret, payload)
		}
	}
}

// TestFormatVaultWithoutUnsealBackends covers the common case where neither optional
// unseal backend is configured, so the nil checks are the only thing standing between
// the formatter and a panic.
func TestFormatVaultWithoutUnsealBackends(t *testing.T) {
	vault := &vaultv1alpha1.Vault{}
	vault.Spec.UnsealConfig.Kubernetes.SecretName = "vault-unseal-keys"

	got := format.FormatVault(vault).(*vaultv1alpha1.Vault)

	if got.Spec.UnsealConfig.Kubernetes.SecretName != "vault-unseal-keys" {
		t.Errorf("kubernetes unseal config was dropped: secretName = %q", got.Spec.UnsealConfig.Kubernetes.SecretName)
	}
}

// TestFormatObjectDispatchesVault covers the GVK-string wiring the controller relies on.
func TestFormatObjectDispatchesVault(t *testing.T) {
	vault := &vaultv1alpha1.Vault{}
	vault.Spec.UnsealConfig.Vault = &vaultv1alpha1.VaultUnsealConfig{Token: "hvs.secret-value"}

	formatted := format.FormatObject(vault, "vault.banzaicloud.com/v1alpha1, Kind=Vault", nil)

	if got := formatted.(*vaultv1alpha1.Vault); got.Spec.UnsealConfig.Vault.Token != "" {
		t.Errorf("FormatObject did not route Vault through FormatVault: token = %q", got.Spec.UnsealConfig.Vault.Token)
	}
}
