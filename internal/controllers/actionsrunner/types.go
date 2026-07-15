package actionsrunner

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Local type stubs for the actions-runner-controller CRDs
// (github.com/actions/actions-runner-controller, API group actions.summerwind.net).
//
// The upstream apis package won't compile against our pinned deps: its webhook files
// target a different controller-runtime than our v0.23.3, and its types expect a
// different k8s than our v0.35.5. Importing it would force a repo-wide upgrade. These
// stubs preserve the full Spec/Status JSON via runtime.RawExtension, which is all the
// agent needs to forward them as assets.

const (
	group   = "actions.summerwind.net"
	version = "v1alpha1"
)

var (
	RunnerGVK           = schema.GroupVersionKind{Group: group, Version: version, Kind: "Runner"}
	RunnerDeploymentGVK = schema.GroupVersionKind{Group: group, Version: version, Kind: "RunnerDeployment"}
	RunnerReplicaSetGVK = schema.GroupVersionKind{Group: group, Version: version, Kind: "RunnerReplicaSet"}
	RunnerSetGVK        = schema.GroupVersionKind{Group: group, Version: version, Kind: "RunnerSet"}

	groupVersion             = schema.GroupVersion{Group: group, Version: version}
	schemeBuilder            = runtime.NewSchemeBuilder(addKnownTypes)
	AddActionsRunnerToScheme = schemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(groupVersion,
		&Runner{}, &RunnerList{},
		&RunnerDeployment{}, &RunnerDeploymentList{},
		&RunnerReplicaSet{}, &RunnerReplicaSetList{},
		&RunnerSet{}, &RunnerSetList{},
	)
	metav1.AddToGroupVersion(s, groupVersion)
	return nil
}

// resource is the shared stub layout for every actions.summerwind.net kind. Spec and
// Status are kept as raw JSON so the object round-trips untouched to the backend.
type resource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              runtime.RawExtension `json:"spec,omitempty"`
	Status            runtime.RawExtension `json:"status,omitempty"`
}

func (r *resource) deepCopyInto(out *resource) {
	out.TypeMeta = r.TypeMeta
	r.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	r.Spec.DeepCopyInto(&out.Spec)
	r.Status.DeepCopyInto(&out.Status)
}

type Runner struct{ resource }

func (r *Runner) DeepCopyObject() runtime.Object {
	if r == nil {
		return nil
	}
	out := &Runner{}
	r.deepCopyInto(&out.resource)
	return out
}

type RunnerDeployment struct{ resource }

func (r *RunnerDeployment) DeepCopyObject() runtime.Object {
	if r == nil {
		return nil
	}
	out := &RunnerDeployment{}
	r.deepCopyInto(&out.resource)
	return out
}

type RunnerReplicaSet struct{ resource }

func (r *RunnerReplicaSet) DeepCopyObject() runtime.Object {
	if r == nil {
		return nil
	}
	out := &RunnerReplicaSet{}
	r.deepCopyInto(&out.resource)
	return out
}

type RunnerSet struct{ resource }

func (r *RunnerSet) DeepCopyObject() runtime.Object {
	if r == nil {
		return nil
	}
	out := &RunnerSet{}
	r.deepCopyInto(&out.resource)
	return out
}

type RunnerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Runner `json:"items"`
}

func (l *RunnerList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &RunnerList{TypeMeta: l.TypeMeta}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]Runner, len(l.Items))
	for i := range l.Items {
		l.Items[i].deepCopyInto(&out.Items[i].resource)
	}
	return out
}

type RunnerDeploymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RunnerDeployment `json:"items"`
}

func (l *RunnerDeploymentList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &RunnerDeploymentList{TypeMeta: l.TypeMeta}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]RunnerDeployment, len(l.Items))
	for i := range l.Items {
		l.Items[i].deepCopyInto(&out.Items[i].resource)
	}
	return out
}

type RunnerReplicaSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RunnerReplicaSet `json:"items"`
}

func (l *RunnerReplicaSetList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &RunnerReplicaSetList{TypeMeta: l.TypeMeta}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]RunnerReplicaSet, len(l.Items))
	for i := range l.Items {
		l.Items[i].deepCopyInto(&out.Items[i].resource)
	}
	return out
}

type RunnerSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RunnerSet `json:"items"`
}

func (l *RunnerSetList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &RunnerSetList{TypeMeta: l.TypeMeta}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]RunnerSet, len(l.Items))
	for i := range l.Items {
		l.Items[i].deepCopyInto(&out.Items[i].resource)
	}
	return out
}
