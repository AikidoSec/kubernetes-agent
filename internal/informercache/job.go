package imformercache

import (
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StripJob replaces an excluded job with an identity-only stub in place. Returning
// a valid Job keeps atomic informer cache replacements working.
func StripJob(job *batchv1.Job) *batchv1.Job {
	*job = batchv1.Job{
		TypeMeta: job.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            job.Name,
			Namespace:       job.Namespace,
			UID:             job.UID,
			ResourceVersion: job.ResourceVersion,
			Annotations:     map[string]string{strippedAnnotation: "true"},
		},
	}
	return job
}
