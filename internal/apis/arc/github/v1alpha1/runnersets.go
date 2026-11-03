package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RunnerSetFields preserves the spec and status across ARC releases while
// exposing Kubernetes metadata, including owner references, to the watcher.
type RunnerSetFields struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              json.RawMessage `json:"spec,omitempty"`
	Status            json.RawMessage `json:"status,omitempty"`
}

func (in *RunnerSetFields) deepCopyInto(out *RunnerSetFields) {
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = append(json.RawMessage(nil), in.Spec...)
	out.Status = append(json.RawMessage(nil), in.Status...)
}

type EphemeralRunnerSet struct {
	metav1.TypeMeta `json:",inline"`
	RunnerSetFields `json:",inline"`
}

func (in *EphemeralRunnerSet) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.RunnerSetFields.deepCopyInto(&out.RunnerSetFields)
	return &out
}

type EphemeralRunnerSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EphemeralRunnerSet `json:"items"`
}

func (in *EphemeralRunnerSetList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]EphemeralRunnerSet, len(in.Items))
		for i := range in.Items {
			out.Items[i] = in.Items[i]
			in.Items[i].RunnerSetFields.deepCopyInto(&out.Items[i].RunnerSetFields)
		}
	}
	return &out
}

type AutoscalingRunnerSet struct {
	metav1.TypeMeta `json:",inline"`
	RunnerSetFields `json:",inline"`
}

func (in *AutoscalingRunnerSet) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.RunnerSetFields.deepCopyInto(&out.RunnerSetFields)
	return &out
}

type AutoscalingRunnerSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AutoscalingRunnerSet `json:"items"`
}

func (in *AutoscalingRunnerSetList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AutoscalingRunnerSet, len(in.Items))
		for i := range in.Items {
			out.Items[i] = in.Items[i]
			in.Items[i].RunnerSetFields.deepCopyInto(&out.Items[i].RunnerSetFields)
		}
	}
	return &out
}
