package v1beta1

import (
	"bytes"
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GroupVersion = schema.GroupVersion{Group: "elbv2.k8s.aws", Version: "v1beta1"}

func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &TargetGroupBinding{}, &TargetGroupBindingList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

type TargetGroupBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              json.RawMessage `json:"spec,omitempty"`
	Status            json.RawMessage `json:"status,omitempty"`
}

func (in *TargetGroupBinding) deepCopyInto(out *TargetGroupBinding) {
	*out = *in
	in.DeepCopyInto(&out.ObjectMeta)
	out.Spec = bytes.Clone(in.Spec)
	out.Status = bytes.Clone(in.Status)
}

func (in *TargetGroupBinding) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(TargetGroupBinding)
	in.deepCopyInto(out)
	return out
}

type TargetGroupBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TargetGroupBinding `json:"items"`
}

func (in *TargetGroupBindingList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]TargetGroupBinding, len(in.Items))
		for i := range in.Items {
			in.Items[i].deepCopyInto(&out.Items[i])
		}
	}
	return &out
}
