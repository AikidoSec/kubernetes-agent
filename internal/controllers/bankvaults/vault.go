package bankvaults

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	vaultv1alpha1 "aikidoSec.kubernetesAgent/internal/apis/bankvaults/v1alpha1"
	"aikidoSec.kubernetesAgent/internal/format"
	"aikidoSec.kubernetesAgent/internal/predicates"
	"aikidoSec.kubernetesAgent/internal/services/logger"
	"aikidoSec.kubernetesAgent/pkg/batchclient"
	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const defaultRequeueAfter = 12 * time.Hour

var VaultGVK = schema.GroupVersionKind{
	Group:   "vault.banzaicloud.com",
	Version: "v1alpha1",
	Kind:    "Vault",
}

// VaultController reconciles Bank-Vaults vault-operator Vault objects. A Vault owns
// the StatefulSet running the Vault cluster and the Deployment running the
// configurer, so it is the root of the ownership chain for those Pods.
type VaultController struct {
	client.Client
	Logger          *logger.Service
	OutputClient    *batchclient.BatchClient
	NamespaceFilter *predicates.NamespaceFilter
	AgentState      *models.AgentState
}

func (r *VaultController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	time.Sleep(200 * time.Millisecond)
	eventTime := time.Now().UTC()

	var vault vaultv1alpha1.Vault
	vault.GetObjectKind().SetGroupVersionKind(VaultGVK)
	vault.SetName(req.Name)
	vault.SetNamespace(req.Namespace)

	objectID := VaultGVK.String() + "/" + req.String()
	requeueAfter := time.Duration(0)

	var obj client.Object = &vault
	var eventType models.EventType
	switch err := r.Get(ctx, req.NamespacedName, &vault); {
	case errors.IsNotFound(err):
		eventType = models.DeletedEventType
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting Vault", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get Vault %v: %w", req.NamespacedName, err)
	default:
		eventType = models.ModifiedEventType
		requeueAfter = defaultRequeueAfter
	}

	// Route through the shared formatter (same boundary the generic Watcher uses) so
	// the unseal credentials carried in the spec are dropped before transmission.
	if eventType == models.ModifiedEventType {
		obj = format.FormatObject(obj, VaultGVK.String(), r.AgentState)
	}

	metadata, err := json.Marshal(obj)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error marshalling Vault", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("error marshalling Vault: %w", err)
	}

	payload := models.AssetPayload{
		ObjectUID: objectID,
		Metadata:  string(metadata),
		EventType: eventType,
		EventTime: eventTime,
	}

	if err := r.OutputClient.SendContext(ctx, payload); err != nil {
		r.Logger.ReportError(ctx, err, "error sending Vault payload", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not send Vault payload: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *VaultController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSecurityWatcher_"+VaultGVK.String()+"_"+uuid.NewString()).
		For(&vaultv1alpha1.Vault{}, builder.WithPredicates(predicates.NewGenericPredicate(r.NamespaceFilter))).
		WithOptions(opts).
		Complete(r)
}
