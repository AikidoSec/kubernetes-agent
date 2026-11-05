package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:object:root=true
type EphemeralRunner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   runtime.RawExtension `json:"spec,omitzero"`
	Status runtime.RawExtension `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type EphemeralRunnerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []EphemeralRunner `json:"items"`
}

// +kubebuilder:object:root=true
type AutoscalingListener struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   runtime.RawExtension `json:"spec,omitzero"`
	Status runtime.RawExtension `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type AutoscalingListenerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AutoscalingListener `json:"items"`
}
