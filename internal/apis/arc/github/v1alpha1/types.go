/*
Copyright 2020 The actions-runner-controller authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EphemeralRunner is the Schema for the ephemeralrunners API
type EphemeralRunner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EphemeralRunnerSpec   `json:"spec,omitempty"`
	Status EphemeralRunnerStatus `json:"status,omitempty"`
}

// EphemeralRunnerSpec defines the desired state of EphemeralRunner
type EphemeralRunnerSpec struct {
	// +required
	GitHubConfigUrl string `json:"githubConfigUrl,omitempty"`

	// +required
	GitHubConfigSecret string `json:"githubConfigSecret,omitempty"`

	// +optional
	GitHubServerTLS *TLSConfig `json:"githubServerTLS,omitempty"`

	// +required
	RunnerScaleSetID int `json:"runnerScaleSetId,omitempty"`

	// +optional
	Proxy *ProxyConfig `json:"proxy,omitempty"`

	// +optional
	ProxySecretRef string `json:"proxySecretRef,omitempty"`

	// +optional
	VaultConfig *VaultConfig `json:"vaultConfig,omitempty"`

	// +optional
	EphemeralRunnerConfigSecretMetadata *ResourceMeta `json:"ephemeralRunnerConfigSecretMetadata,omitempty"`

	corev1.PodTemplateSpec `json:",inline"`
}

// EphemeralRunnerStatus defines the observed state of EphemeralRunner
type EphemeralRunnerStatus struct {
	// Turns true only if the runner is online.
	// +optional
	Ready bool `json:"ready"`
	// Phase describes phases where EphemeralRunner can be in.
	// The underlying type is a PodPhase, but the meaning is more restrictive
	//
	// The PodFailed phase should be set only when EphemeralRunner fails to start
	// after multiple retries. That signals that this EphemeralRunner won't work,
	// and manual inspection is required
	//
	// The PodSucceded phase should be set only when confirmed that EphemeralRunner
	// actually executed the job and has been removed from the service.
	// +optional
	Phase EphemeralRunnerPhase `json:"phase,omitempty"`
	// +optional
	Reason string `json:"reason,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`

	// +optional
	RunnerID int `json:"runnerId,omitempty"`
	// +optional
	RunnerName string `json:"runnerName,omitempty"`

	// +optional
	Failures map[string]metav1.Time `json:"failures,omitempty"`

	// +optional
	JobRequestID int64 `json:"jobRequestId,omitempty"`

	// +optional
	JobID string `json:"jobId,omitempty"`

	// +optional
	JobRepositoryName string `json:"jobRepositoryName,omitempty"`

	// +optional
	JobWorkflowRef string `json:"jobWorkflowRef,omitempty"`

	// +optional
	WorkflowRunID int64 `json:"workflowRunId,omitempty"`

	// +optional
	JobDisplayName string `json:"jobDisplayName,omitempty"`
}

// EphemeralRunnerPhase is the phase of the ephemeral runner.
// It must be a superset of the pod phase.
type EphemeralRunnerPhase string

// EphemeralRunnerList contains a list of EphemeralRunner
type EphemeralRunnerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EphemeralRunner `json:"items"`
}

// AutoscalingListenerSpec defines the desired state of AutoscalingListener
type AutoscalingListenerSpec struct {
	// Required
	GitHubConfigUrl string `json:"githubConfigUrl,omitempty"`

	// Required
	GitHubConfigSecret string `json:"githubConfigSecret,omitempty"`

	// Required
	RunnerScaleSetId int `json:"runnerScaleSetId,omitempty"`

	// Required
	AutoscalingRunnerSetNamespace string `json:"autoscalingRunnerSetNamespace,omitempty"`

	// Required
	AutoscalingRunnerSetName string `json:"autoscalingRunnerSetName,omitempty"`

	// Required
	EphemeralRunnerSetName string `json:"ephemeralRunnerSetName,omitempty"`

	// Required
	// +kubebuilder:validation:Minimum:=0
	MaxRunners int `json:"maxRunners,omitempty"`

	// Required
	// +kubebuilder:validation:Minimum:=0
	MinRunners int `json:"minRunners,omitempty"`

	// Required
	Image string `json:"image,omitempty"`

	// Required
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// +optional
	Proxy *ProxyConfig `json:"proxy,omitempty"`

	// +optional
	GitHubServerTLS *TLSConfig `json:"githubServerTLS,omitempty"`

	// +optional
	VaultConfig *VaultConfig `json:"vaultConfig,omitempty"`

	// +optional
	Metrics *MetricsConfig `json:"metrics,omitempty"`

	// +optional
	Template *corev1.PodTemplateSpec `json:"template,omitempty"`

	// +optional
	ConfigSecretMetadata *ResourceMeta `json:"configSecretMetadata,omitempty"`

	// +optional
	ServiceAccountMetadata *ResourceMeta `json:"serviceAccountMetadata,omitempty"`

	// +optional
	RoleMetadata *ResourceMeta `json:"roleMetadata,omitempty"`

	// +optional
	RoleBindingMetadata *ResourceMeta `json:"roleBindingMetadata,omitempty"`
}

// AutoscalingListenerStatus defines the observed state of AutoscalingListener
type AutoscalingListenerStatus struct{}

// AutoscalingListener is the Schema for the autoscalinglisteners API
type AutoscalingListener struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AutoscalingListenerSpec   `json:"spec,omitempty"`
	Status AutoscalingListenerStatus `json:"status,omitempty"`
}

// AutoscalingListenerList contains a list of AutoscalingListener
type AutoscalingListenerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AutoscalingListener `json:"items"`
}

// ResourceMeta carries metadata common to all internal resources
type ResourceMeta struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type TLSConfig struct {
	// Required
	CertificateFrom *TLSCertificateSource `json:"certificateFrom,omitempty"`
}

type TLSCertificateSource struct {
	// Required
	ConfigMapKeyRef *corev1.ConfigMapKeySelector `json:"configMapKeyRef,omitempty"`
}

type ProxyConfig struct {
	// +optional
	HTTP *ProxyServerConfig `json:"http,omitempty"`

	// +optional
	HTTPS *ProxyServerConfig `json:"https,omitempty"`

	// +optional
	NoProxy []string `json:"noProxy,omitempty"`
}

type ProxyServerConfig struct {
	// Required
	Url string `json:"url,omitempty"`

	// +optional
	CredentialSecretRef string `json:"credentialSecretRef,omitempty"`
}

// VaultType mirrors github.com/actions/actions-runner-controller/vault.VaultType,
// a string-underlying type. Mirrored locally to avoid importing the upstream module.
type VaultType string

type VaultConfig struct {
	// +optional
	Type VaultType `json:"type,omitempty"`
	// +optional
	AzureKeyVault *AzureKeyVaultConfig `json:"azureKeyVault,omitempty"`
	// +optional
	Proxy *ProxyConfig `json:"proxy,omitempty"`
}

type AzureKeyVaultConfig struct {
	// +required
	URL string `json:"url,omitempty"`
	// +required
	TenantID string `json:"tenantId,omitempty"`
	// +required
	ClientID string `json:"clientId,omitempty"`
	// +required
	CertificatePath string `json:"certificatePath,omitempty"`
}

// MetricsConfig holds configuration parameters for each metric type
type MetricsConfig struct {
	// +optional
	Counters map[string]*CounterMetric `json:"counters,omitempty"`
	// +optional
	Gauges map[string]*GaugeMetric `json:"gauges,omitempty"`
	// +optional
	Histograms map[string]*HistogramMetric `json:"histograms,omitempty"`
}

// CounterMetric holds configuration of a single metric of type Counter
type CounterMetric struct {
	Labels []string `json:"labels"`
}

// GaugeMetric holds configuration of a single metric of type Gauge
type GaugeMetric struct {
	Labels []string `json:"labels"`
}

// HistogramMetric holds configuration of a single metric of type Histogram
type HistogramMetric struct {
	Labels  []string  `json:"labels"`
	Buckets []float64 `json:"buckets,omitempty"`
}
