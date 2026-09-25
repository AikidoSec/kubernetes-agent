package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	opensearchv1 "aikidoSec.kubernetesAgent/internal/apis/opensearch/v1"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
)

const defaultRequeueAfter = 12 * time.Hour

var OpenSearchClusterGVK = schema.GroupVersionKind{
	Group:   "opensearch.opster.io",
	Version: "v1",
	Kind:    "OpenSearchCluster",
}

// OpenSearchClusterController reconciles OpenSearch operator OpenSearchCluster objects.
// The operator's bootstrap pod is owned by the cluster CR directly rather than by a
// Deployment or StatefulSet, so without this watcher that pod's owner chain ends at a
// resource the agent never collected.
type OpenSearchClusterController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
}

func (r *OpenSearchClusterController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var cluster opensearchv1.OpenSearchCluster
	cluster.GetObjectKind().SetGroupVersionKind(OpenSearchClusterGVK)
	cluster.SetName(req.Name)
	cluster.SetNamespace(req.Namespace)

	objectID := OpenSearchClusterGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &cluster); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting OpenSearchCluster", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get OpenSearchCluster %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	metadata, err := json.Marshal(cluster)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling OpenSearchCluster", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling OpenSearchCluster: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending OpenSearchCluster payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send OpenSearchCluster payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *OpenSearchClusterController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+OpenSearchClusterGVK.String()+"_"+uuid.NewString()).
		For(&opensearchv1.OpenSearchCluster{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
