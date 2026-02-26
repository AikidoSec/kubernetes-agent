package openshift

import (
	"context"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

var ImageContentSourcePolicyGVK = schema.GroupVersionKind{
	Group:   operatorv1alpha1.GroupName,
	Version: operatorv1alpha1.GroupVersion.Version,
	Kind:    "ImageContentSourcePolicy",
}

// ImageContentSourcePolicyController reconciles an OpenShift ImageContentSourcePolicy object.
type ImageContentSourcePolicyController struct {
	client.Client
	*models.AgentState
	Logger *logger.Service
}

func (r *ImageContentSourcePolicyController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add a small delay before processing the event to wait for the cache sync since it lags behind by definition.
	time.Sleep(200 * time.Millisecond)

	var policy operatorv1alpha1.ImageContentSourcePolicy
	switch err := r.Get(ctx, req.NamespacedName, &policy); {
	case errors.IsNotFound(err):
		// This should not really happen.
		return ctrl.Result{}, nil
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	}

	mappings := make(map[string]string)
	for _, repo := range policy.Spec.RepositoryDigestMirrors {
		if len(repo.Mirrors) == 0 {
			continue
		}

		mappings[repo.Source] = repo.Mirrors[0]
	}

	r.SetImageMirrorMappings(mappings)

	return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageContentSourcePolicyController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_" + ImageContentSourcePolicyGVK.String() + "_" + uuid.NewString()).
		For(&operatorv1alpha1.ImageContentSourcePolicy{}).
		WithOptions(opts).
		Complete(r)
}
