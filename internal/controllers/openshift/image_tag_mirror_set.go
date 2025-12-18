package openshift

import (
	"context"
	"fmt"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	v1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var ImageTagMirrorSetGVK = schema.GroupVersionKind{
	Group:   v1.GroupName,
	Version: v1.GroupVersion.Version,
	Kind:    "ImageTagMirrorSet",
}

// ImageTagMirrorSetController reconciles an OpenShift ImageContentSourcePolicy object.
type ImageTagMirrorSetController struct {
	client.Client
	*models.AgentState
	Logger *logger.Service
}

func (r *ImageTagMirrorSetController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add a small delay before processing the event to wait for the cache sync since it lags behind by definition.
	time.Sleep(200 * time.Millisecond)

	var set v1.ImageTagMirrorSet
	switch err := r.Get(ctx, req.NamespacedName, &set); {
	case errors.IsNotFound(err):
		// This should not really happen.
		return ctrl.Result{}, nil
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	}

	mappings := make(map[string]string)
	for _, mirror := range set.Spec.ImageTagMirrors {
		if len(mirror.Mirrors) == 0 {
			continue
		}

		mappings[mirror.Source] = string(mirror.Mirrors[0])
	}

	r.SetImageMirrorMappings(mappings)

	return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageTagMirrorSetController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_" + ImageTagMirrorSetGVK.String() + "_" + uuid.NewString()).
		For(&v1.ImageTagMirrorSet{}).
		WithOptions(opts).
		Complete(r)
}
