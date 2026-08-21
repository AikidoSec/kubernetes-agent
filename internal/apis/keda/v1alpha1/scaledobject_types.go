/*
Copyright 2021 The KEDA Authors

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
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScaledObject is a specification for a ScaledObject resource
type ScaledObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ScaledObjectSpec `json:"spec"`
	// +optional
	Status ScaledObjectStatus `json:"status,omitempty"`
}

// HealthStatus is the status for a ScaledObject's health
type HealthStatus struct {
	// +optional
	NumberOfFailures *int32 `json:"numberOfFailures,omitempty"`
	// +optional
	Status HealthStatusType `json:"status,omitempty"`
}

// TriggerActivityStatus represents the activity status of an external trigger
type TriggerActivityStatus struct {
	// +optional
	IsActive bool `json:"isActive"`
}

// HealthStatusType is an indication of whether the health status is happy or failing
type HealthStatusType string

// ScaledObjectSpec is the spec for a ScaledObject resource
// +kubebuilder:validation:XValidation:rule="!has(self.minReplicaCount) || self.minReplicaCount <= (has(self.maxReplicaCount) ? self.maxReplicaCount : 100)",message="minReplicaCount must be less than or equal to maxReplicaCount"
type ScaledObjectSpec struct {
	ScaleTargetRef *ScaleTarget `json:"scaleTargetRef"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	PollingInterval *int32 `json:"pollingInterval,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	InitialCooldownPeriod *int32 `json:"initialCooldownPeriod,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	CooldownPeriod *int32 `json:"cooldownPeriod,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	IdleReplicaCount *int32 `json:"idleReplicaCount,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	MinReplicaCount *int32 `json:"minReplicaCount,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	MaxReplicaCount *int32 `json:"maxReplicaCount,omitempty"`
	// +optional
	Advanced *AdvancedConfig `json:"advanced,omitempty"`

	// +kubebuilder:validation:MinItems=1
	Triggers []ScaleTriggers `json:"triggers"`
	// +optional
	Fallback *Fallback `json:"fallback,omitempty"`
}

// Fallback is the spec for fallback options
type Fallback struct {
	// +kubebuilder:validation:Minimum=0
	FailureThreshold int32 `json:"failureThreshold"`
	// +kubebuilder:validation:Minimum=0
	Replicas int32 `json:"replicas"`
	// +optional
	// +kubebuilder:default=static
	// +kubebuilder:validation:Enum=static;currentReplicas;currentReplicasIfHigher;currentReplicasIfLower;scalingModifiers
	Behavior string `json:"behavior,omitempty"`
}

// AdvancedConfig specifies advance scaling options
type AdvancedConfig struct {
	// +optional
	HorizontalPodAutoscalerConfig *HorizontalPodAutoscalerConfig `json:"horizontalPodAutoscalerConfig,omitempty"`
	// +optional
	RestoreToOriginalReplicaCount bool `json:"restoreToOriginalReplicaCount,omitempty"`
	// +optional
	ScalingModifiers ScalingModifiers `json:"scalingModifiers,omitempty"`
}

// ScalingModifiers describes advanced scaling logic options like formula
type ScalingModifiers struct {
	Formula string `json:"formula,omitempty"`
	Target  string `json:"target,omitempty"`
	// +optional
	ActivationTarget string `json:"activationTarget,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=AverageValue;Value
	MetricType autoscalingv2.MetricTargetType `json:"metricType,omitempty"`
}

// HorizontalPodAutoscalerConfig specifies horizontal scale config
type HorizontalPodAutoscalerConfig struct {
	// +optional
	Behavior *autoscalingv2.HorizontalPodAutoscalerBehavior `json:"behavior,omitempty"`
	// +optional
	Name string `json:"name,omitempty"`
}

// ScaleTarget holds the reference to the scale target Object
type ScaleTarget struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`
	// +optional
	Kind string `json:"kind,omitempty"`
	// +optional
	EnvSourceContainerName string `json:"envSourceContainerName,omitempty"`
}

// +k8s:openapi-gen=true

// ScaledObjectStatus is the status for a ScaledObject resource
// +optional
type ScaledObjectStatus struct {
	// +optional
	ScaleTargetKind string `json:"scaleTargetKind,omitempty"`
	// +optional
	ScaleTargetGVKR *GroupVersionKindResource `json:"scaleTargetGVKR,omitempty"`
	// +optional
	OriginalReplicaCount *int32 `json:"originalReplicaCount,omitempty"`
	// +optional
	LastActiveTime *metav1.Time `json:"lastActiveTime,omitempty"`
	// +optional
	ExternalMetricNames []string `json:"externalMetricNames,omitempty"`
	// +optional
	ResourceMetricNames []string `json:"resourceMetricNames,omitempty"`
	// +optional
	CompositeScalerName string `json:"compositeScalerName,omitempty"`
	// +optional
	Conditions Conditions `json:"conditions,omitempty"`
	// +optional
	Health map[string]HealthStatus `json:"health,omitempty"`
	// +optional
	TriggersActivity map[string]TriggerActivityStatus `json:"triggersActivity,omitempty"`
	// +optional
	PausedReplicaCount *int32 `json:"pausedReplicaCount,omitempty"`
	// +optional
	HpaName string `json:"hpaName,omitempty"`
	// +optional
	TriggersTypes *string `json:"triggersTypes,omitempty"`
	// +optional
	AuthenticationsTypes *string `json:"authenticationsTypes,omitempty"`
}

// +kubebuilder:object:root=true

// ScaledObjectList is a list of ScaledObject resources
type ScaledObjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ScaledObject `json:"items"`
}
