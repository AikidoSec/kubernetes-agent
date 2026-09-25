package predicates_test

import (
	"testing"

	ghv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/github/v1alpha1"
	swv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/arc/summerwind/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/controllers/argoproj"
	imformercache "aikidoSec.kubernetesAgent/internal/informercache"
	"aikidoSec.kubernetesAgent/internal/predicates"
	batchv1 "k8s.io/api/batch/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type testLogger struct{}

func (l *testLogger) LogWarning(_ error, _ string, _ ...any) {}

func TestNamespaceFilterIsObjectExcluded(t *testing.T) {
	tests := []struct {
		name               string
		obj                *unstructured.Unstructured
		excludedNamespaces []string
		includedNamespaces []string
		want               bool
	}{
		{
			name: "namespace is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               true,
		},
		{
			name: "namespace is not excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "default",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               false,
		},
		{
			name: "empty namespace",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name": "test-resource",
					},
				},
			},
			excludedNamespaces: []string{"kube-system"},
			want:               false,
		},
		{
			name: "empty excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{},
			want:               false,
		},
		{
			name: "nil excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: nil,
			want:               false,
		},
		{
			name: "namespace is excluded with wildcard",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"kube-*"},
			want:               true,
		},
		{
			name: "namespace is excluded with wildcard (2)",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"*-system"},
			want:               true,
		},
		{
			name: "namespace list invalid pattern is ignored",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"[!-system*"},
			want:               false,
		},
		{
			name: "namespace list invalid pattern is ignored (2)",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"[!-system*", "kub**"},
			want:               true,
		},
		{
			name: "included namespace is not excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "app-ns",
					},
				},
			},
			includedNamespaces: []string{"app-ns", "web-ns"},
			want:               false,
		},
		{
			name: "namespace not in include list is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			includedNamespaces: []string{"app-ns", "web-ns"},
			want:               true,
		},
		{
			name: "included namespace with wildcard",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "app-staging",
					},
				},
			},
			includedNamespaces: []string{"app-*"},
			want:               false,
		},
		{
			name: "namespace not matching include wildcard is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			includedNamespaces: []string{"app-*"},
			want:               true,
		},
		{
			name: "empty namespace with include filter",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name": "test-resource",
					},
				},
			},
			includedNamespaces: []string{"app-ns"},
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := predicates.NewNamespaceFilter(&testLogger{}, tt.excludedNamespaces, tt.includedNamespaces)
			got := n.IsObjectExcluded(tt.obj)
			if got != tt.want {
				t.Errorf("NamespaceFilter.IsObjectExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsSpecModifiedTypedObjects covers the typed objects controller-runtime hands to
// For(&Typed{}) vendor-CRD watches — the case that previously always returned false,
// leaving CRD spec edits un-enqueued until the scheduled requeue.
func TestIsSpecModifiedTypedObjects(t *testing.T) {
	ephemeralRunner := func(url string) client.Object {
		er := &ghv1alpha1.EphemeralRunner{}
		er.Spec.GitHubConfigUrl = url
		return er
	}

	// ArgoCD Application stores its spec as runtime.RawExtension.
	application := func(specJSON string) client.Object {
		return &argoproj.Application{Spec: runtime.RawExtension{Raw: []byte(specJSON)}}
	}

	runnerWithMTU := func(mtu int64) client.Object {
		r := &swv1alpha1.Runner{}
		r.Spec.DockerMTU = &mtu
		return r
	}

	tests := []struct {
		name     string
		old, new client.Object
		want     bool
	}{
		{
			name: "typed EphemeralRunner spec change enqueues",
			old:  ephemeralRunner("https://github.com/old"),
			new:  ephemeralRunner("https://github.com/new"),
			want: true,
		},
		{
			name: "typed EphemeralRunner unchanged spec is dropped",
			old:  ephemeralRunner("https://github.com/same"),
			new:  ephemeralRunner("https://github.com/same"),
			want: false,
		},
		{
			name: "RawExtension Application spec change enqueues",
			old:  application(`{"project":"default"}`),
			new:  application(`{"project":"prod"}`),
			want: true,
		},
		{
			name: "RawExtension Application unchanged spec is dropped",
			old:  application(`{"project":"default"}`),
			new:  application(`{"project":"default"}`),
			want: false,
		},
		{
			name: "int64 spec change above 2^53 is detected",
			old:  runnerWithMTU(1 << 53),
			new:  runnerWithMTU((1 << 53) + 2),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new}
			if got := predicates.IsSpecModified(e); got != tt.want {
				t.Errorf("IsSpecModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStrippedObjectPredicates(t *testing.T) {
	filter := predicates.NewNamespaceFilter(&testLogger{}, []string{"excluded"}, nil)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: "sha256:abc"}}}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod.Spec}}}
	toUnstructured := func(obj client.Object) client.Object {
		t.Helper()
		data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			t.Fatal(err)
		}
		return &unstructured.Unstructured{Object: data}
	}
	for _, tc := range []struct {
		name       string
		pred       predicate.Predicate
		live, stub client.Object
	}{
		{"pod", predicates.NewPodPredicate(filter), toUnstructured(pod), toUnstructured(imformercache.StripPod(pod.DeepCopy()))},
		{"job unstructured", predicates.NewGenericPredicate(filter), toUnstructured(job), toUnstructured(imformercache.StripJob(job.DeepCopy()))},
		{"job typed", predicates.NewGenericPredicate(filter), job, imformercache.StripJob(job.DeepCopy())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, initial := range []bool{false, true} {
				if tc.pred.Create(event.CreateEvent{Object: tc.stub, IsInInitialList: initial}) {
					t.Fatal("stub create was accepted")
				}
				if !tc.pred.Create(event.CreateEvent{Object: tc.live, IsInInitialList: initial}) {
					t.Fatal("eligible create was rejected")
				}
			}
			if tc.pred.Create(event.CreateEvent{}) {
				t.Fatal("nil create was accepted")
			}
			if tc.pred.Update(event.UpdateEvent{ObjectOld: tc.live}) {
				t.Fatal("nil update was accepted")
			}
			if tc.pred.Update(event.UpdateEvent{ObjectOld: tc.live, ObjectNew: tc.stub}) {
				t.Fatal("live-to-stub update was accepted")
			}
			if tc.pred.Update(event.UpdateEvent{ObjectOld: tc.stub, ObjectNew: tc.stub}) {
				t.Fatal("stub-to-stub update was accepted")
			}
			if !tc.pred.Update(event.UpdateEvent{ObjectOld: tc.stub, ObjectNew: tc.live}) {
				t.Fatal("stub becoming eligible was rejected")
			}
			// Deletion still needs to remove assets that may have been reported earlier.
			if !tc.pred.Delete(event.DeleteEvent{Object: tc.stub}) {
				t.Fatal("stub deletion was rejected")
			}
			excluded := tc.live.DeepCopyObject().(client.Object)
			excluded.SetNamespace("excluded")
			if tc.pred.Create(event.CreateEvent{Object: excluded}) || tc.pred.Update(event.UpdateEvent{ObjectOld: tc.stub, ObjectNew: excluded}) {
				t.Fatal("namespace exclusion was bypassed")
			}
		})
	}
}

func TestConfigMapPredicate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		exclude, include []string
		want             bool
	}{
		{name: "allowed", want: true},
		{name: "excluded", exclude: []string{"app-*"}},
		{name: "included", include: []string{"app-*"}, want: true},
		{name: "not included", include: []string{"other-*"}},
	} {
		for _, representation := range []string{"typed", "unstructured"} {
			t.Run(tt.name+"/"+representation, func(t *testing.T) {
				filter := predicates.NewNamespaceFilter(&testLogger{}, tt.exclude, tt.include)
				p := predicates.GetPredicatesForGVK("/v1, Kind=ConfigMap", filter)
				asObject := func(cm *corev1.ConfigMap) client.Object {
					if representation == "typed" {
						return cm
					}
					obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cm)
					if err != nil {
						t.Fatal(err)
					}
					return &unstructured.Unstructured{Object: obj}
				}
				old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "app-prod"}, Data: map[string]string{"key": "old"}}
				if got := p.Create(event.CreateEvent{Object: asObject(old)}); got != tt.want {
					t.Errorf("Create() = %v, want %v", got, tt.want)
				}
				if got := p.Delete(event.DeleteEvent{Object: asObject(old)}); got != tt.want {
					t.Errorf("Delete() = %v, want %v", got, tt.want)
				}
				for _, update := range []struct {
					name   string
					mutate func(*corev1.ConfigMap)
					want   bool
				}{
					{name: "unchanged", mutate: func(_ *corev1.ConfigMap) {}},
					{name: "resource version only", mutate: func(o *corev1.ConfigMap) { o.ResourceVersion = "2" }},
					{name: "data added", mutate: func(o *corev1.ConfigMap) { o.Data["other"] = "value" }, want: true},
					{name: "data changed", mutate: func(o *corev1.ConfigMap) { o.Data["key"] = "new" }, want: true},
					{name: "data removed", mutate: func(o *corev1.ConfigMap) { o.Data = nil }, want: true},
					// Binary data is stripped from the reported asset by FormatConfigMap.
					{name: "binary data only", mutate: func(o *corev1.ConfigMap) { o.BinaryData = map[string][]byte{"key": {1, 2}} }},
					{name: "immutable enabled", mutate: func(o *corev1.ConfigMap) { v := true; o.Immutable = &v }, want: true},
					{name: "labels changed", mutate: func(o *corev1.ConfigMap) { o.Labels = map[string]string{"team": "platform"} }, want: true},
					{name: "annotations changed", mutate: func(o *corev1.ConfigMap) { o.Annotations = map[string]string{"owner": "platform"} }, want: true},
				} {
					t.Run(update.name, func(t *testing.T) {
						next := old.DeepCopy()
						update.mutate(next)
						want := tt.want && update.want
						if got := p.Update(event.UpdateEvent{ObjectOld: asObject(old), ObjectNew: asObject(next)}); got != want {
							t.Errorf("Update() = %v, want %v", got, want)
						}
					})
				}
			})
		}
	}
}
