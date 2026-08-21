package v1alpha1

// Mirrors api/common/v1alpha1 and api/konnect/v1alpha2.

// ControlPlaneRef is a reference to a ControlPlane.
type ControlPlaneRef struct {
	// Type indicates the type of the control plane being referenced. Allowed values:
	// - konnectID
	// - konnectNamespacedRef
	// - kic
	//
	// The default is kic, which implies that the Control Plane is KIC.
	//
	// +optional
	// +kubebuilder:validation:Enum=konnectID;konnectNamespacedRef;kic
	// +kubebuilder:default:=kic
	Type string `json:"type,omitempty"`

	// KonnectID is the schema for the KonnectID type.
	// This field is required when the Type is konnectID.
	// +optional
	KonnectID *KonnectIDType `json:"konnectID,omitempty"`

	// KonnectNamespacedRef is a reference to a Konnect Control Plane entity inside the cluster.
	// It contains the name of the Konnect Control Plane.
	// This field is required when the Type is konnectNamespacedRef.
	// +optional
	KonnectNamespacedRef *KonnectNamespacedRef `json:"konnectNamespacedRef,omitempty"`
}

// KonnectIDType is the schema for the KonnectID type.
type KonnectIDType string

// KonnectNamespacedRef is a reference to a Konnect Control Plane entity inside the cluster.
type KonnectNamespacedRef struct {
	// Name is the name of the Konnect Control Plane.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the namespace where the Konnect Control Plane is in.
	// Currently only cluster scoped resources (KongVault) are allowed to set `konnectNamespacedRef.namespace`.
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// NameRef is a reference to another object representing a Kong entity with deterministic type.
type NameRef struct {
	// Name is the name of the entity.
	//
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// Tags is an optional set of strings associated with an entity for grouping and filtering.
type Tags []string

// ServiceRef is a reference to a KongService.
type ServiceRef struct {
	// Type can be one of:
	// - namespacedRef
	//
	// +kubebuilder:validation:Enum:=namespacedRef
	Type string `json:"type,omitempty"`

	// NamespacedRef is a reference to a KongService.
	NamespacedRef *NameRef `json:"namespacedRef,omitempty"`
}

// KonnectEntityStatus represents the status of a Konnect entity.
type KonnectEntityStatus struct {
	// ID is the unique identifier of the Konnect entity as assigned by Konnect API.
	// If it's unset (empty string), it means the Konnect entity hasn't been created yet.
	//
	// +optional
	ID string `json:"id,omitempty"`

	// ServerURL is the URL of the Konnect server in which the entity exists.
	//
	// +optional
	ServerURL string `json:"serverURL,omitempty"`

	// OrgID is ID of Konnect Org that this entity has been created in.
	//
	// +optional
	OrgID string `json:"organizationID,omitempty"`
}

// KonnectEntityStatusWithControlPlaneRef is a Konnect entity status with a control plane reference.
type KonnectEntityStatusWithControlPlaneRef struct {
	KonnectEntityStatus `json:",inline"`

	// ControlPlaneID is the Konnect ID of the ControlPlane this Route is associated with.
	//
	// +optional
	ControlPlaneID string `json:"controlPlaneID,omitempty"`
}

// KonnectEntityStatusWithControlPlaneAndServiceRefs is a Konnect entity status with
// control plane and service references.
type KonnectEntityStatusWithControlPlaneAndServiceRefs struct {
	KonnectEntityStatus `json:",inline"`

	// ControlPlaneID is the Konnect ID of the ControlPlane this entity is associated with.
	//
	// +optional
	ControlPlaneID string `json:"controlPlaneID,omitempty"`

	// ServiceID is the Konnect ID of the Service this entity is associated with.
	//
	// +optional
	ServiceID string `json:"serviceID,omitempty"`
}
