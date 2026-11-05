package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:object:root=true
type ScaledObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   runtime.RawExtension `json:"spec,omitzero"`
	Status runtime.RawExtension `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type ScaledObjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ScaledObject `json:"items"`
}

// +kubebuilder:object:root=true
type ScaledJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   runtime.RawExtension `json:"spec,omitzero"`
	Status runtime.RawExtension `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type ScaledJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ScaledJob `json:"items"`
}
