package imformercache

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StripJob replaces an excluded job with an identity-only stub in place. Returning
// a valid Job keeps atomic informer cache replacements working.
func StripJob(pod *batchv1.Job) *batchv1.Job {
	*pod = batchv1.Job{
		TypeMeta: pod.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			UID:             pod.UID,
			ResourceVersion: pod.ResourceVersion,
			Annotations:     map[string]string{strippedAnnotation: "true"},
		},
	}
	return pod
}

// IsJobFinished reports whether a Job has reached a terminal condition.
// CompletionTime alone does not cover failed Jobs. FailureTarget and
// SuccessCriteriaMet are not terminal: Pods may still be terminating.
func IsJobFinished(job *batchv1.Job) bool {
	for _, condition := range job.Status.Conditions {
		if condition.Status == corev1.ConditionTrue &&
			(condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) {
			return true
		}
	}
	return false
}
