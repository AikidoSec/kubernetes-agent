package v1

import (
	"bytes"
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GroupVersion = schema.GroupVersion{Group: "networking.istio.io", Version: "v1"}

func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &Gateway{}, &GatewayList{}, &VirtualService{}, &VirtualServiceList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

// RoutingFields preserves the spec and status without dropping fields from newer Istio releases.
type RoutingFields struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              json.RawMessage `json:"spec,omitempty"`
	Status            json.RawMessage `json:"status,omitempty"`
}

func (in *RoutingFields) deepCopyInto(out *RoutingFields) {
	in.DeepCopyInto(&out.ObjectMeta)
	out.Spec = bytes.Clone(in.Spec)
	out.Status = bytes.Clone(in.Status)
}

type Gateway struct {
	metav1.TypeMeta `json:",inline"`
	RoutingFields   `json:",inline"`
}

func (in *Gateway) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.deepCopyInto(&out.RoutingFields)
	return &out
}

type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

func (in *GatewayList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]Gateway, len(in.Items))
		copy(out.Items, in.Items)
		for i := range in.Items {
			in.Items[i].deepCopyInto(&out.Items[i].RoutingFields)
		}
	}
	return &out
}

type VirtualService struct {
	metav1.TypeMeta `json:",inline"`
	RoutingFields   `json:",inline"`
}

func (in *VirtualService) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.deepCopyInto(&out.RoutingFields)
	return &out
}

type VirtualServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualService `json:"items"`
}

func (in *VirtualServiceList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]VirtualService, len(in.Items))
		copy(out.Items, in.Items)
		for i := range in.Items {
			in.Items[i].deepCopyInto(&out.Items[i].RoutingFields)
		}
	}
	return &out
}
