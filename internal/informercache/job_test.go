package imformercache

import (
	"context"
	"reflect"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/features"
	featuretesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/tools/cache"
)

func TestStripJob(t *testing.T) {
	job := &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{Name: "excluded", Namespace: "default", UID: "uid", ResourceVersion: "42", Labels: map[string]string{"large": "data"}, Annotations: map[string]string{"large": "data"}, Finalizers: []string{"cleanup"}},
		Spec:       batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}}}},
		Status:     batchv1.JobStatus{Succeeded: 1},
	}
	want := &batchv1.Job{TypeMeta: job.TypeMeta, ObjectMeta: metav1.ObjectMeta{Name: "excluded", Namespace: "default", UID: "uid", ResourceVersion: "42", Annotations: map[string]string{strippedAnnotation: "true"}}}
	if StripJob(job) != job {
		t.Fatal("must strip in place")
	}
	if !reflect.DeepEqual(job, want) {
		t.Fatalf("got %#v, want identity-only stub %#v", job, want)
	}
	StripJob(job)
	if !reflect.DeepEqual(job, want) {
		t.Fatal("stripping must be idempotent")
	}
}

func TestIsObjectStripped(t *testing.T) {
	for _, obj := range []runtime.Object{StripPod(&corev1.Pod{}), StripJob(&batchv1.Job{})} {
		if !IsObjectStripped(obj.(metav1.Object)) {
			t.Fatalf("typed %T stub not recognized", obj)
		}
		data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: data}
		if !IsObjectStripped(u) {
			t.Fatal("unstructured stub not recognized")
		}
		u.SetAnnotations(map[string]string{strippedAnnotation: "false"})
		if IsObjectStripped(u) {
			t.Fatal("false marker recognized as stripped")
		}
		u.SetAnnotations(nil)
		if IsObjectStripped(u) {
			t.Fatal("unmarked object recognized as stripped")
		}
	}
}

// A single excluded Job must not invalidate the atomic initial cache population.
func TestAtomicInitialListWithStrippedJob(t *testing.T) {
	featuretesting.SetFeatureDuringTest(t, features.InOrderInformers, true)
	featuretesting.SetFeatureDuringTest(t, features.InOrderInformersBatchProcess, true)
	start := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	recent := metav1.NewTime(start.Add(-time.Hour))
	old := metav1.NewTime(start.AddDate(0, 0, -6))
	jobs := []batchv1.Job{
		{ObjectMeta: metav1.ObjectMeta{Name: "running-1", ResourceVersion: "1", CreationTimestamp: recent}, Status: batchv1.JobStatus{Active: 1}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old-active", ResourceVersion: "1", CreationTimestamp: old}, Status: batchv1.JobStatus{Active: 1}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old-complete", ResourceVersion: "1", CreationTimestamp: old}, Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old-failed", ResourceVersion: "1", CreationTimestamp: old}, Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "running-2", ResourceVersion: "1", CreationTimestamp: recent}, Status: batchv1.JobStatus{Active: 1}},
	}
	lw := &cache.ListWatch{
		ListFunc: func(metav1.ListOptions) (runtime.Object, error) {
			return &batchv1.JobList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: jobs}, nil
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			w := watch.NewRaceFreeFake()
			if opts.SendInitialEvents != nil && *opts.SendInitialEvents {
				for i := range jobs {
					w.Add(jobs[i].DeepCopy())
				}
				w.Action(watch.Bookmark, &batchv1.Job{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1", Annotations: map[string]string{metav1.InitialEventsAnnotationKey: "true"}}})
			}
			return w, nil
		},
	}
	informer := cache.NewSharedIndexInformer(lw, &batchv1.Job{}, 0, cache.Indexers{})
	if err := informer.SetTransform(func(obj any) (any, error) {
		job := obj.(*batchv1.Job)
		if job.CreationTimestamp.Time.Before(start.AddDate(0, 0, -5)) {
			return StripJob(job), nil
		}
		return job, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); informer.Run(ctx.Done()) }()
	defer func() { cancel(); <-done }()
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("cache did not sync")
	}
	if got := len(informer.GetStore().List()); got != len(jobs) {
		t.Fatalf("cached %d jobs, want %d", got, len(jobs))
	}
	for name, stripped := range map[string]bool{"running-1": false, "old-active": true, "old-complete": true, "old-failed": true, "running-2": false} {
		obj, exists, err := informer.GetStore().GetByKey(name)
		if err != nil || !exists {
			t.Fatalf("missing %s: %v", name, err)
		}
		if IsObjectStripped(obj.(*batchv1.Job)) != stripped {
			t.Fatalf("wrong stripped state for %s", name)
		}
	}
}
