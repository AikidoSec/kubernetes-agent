package v1

// The agent watches OpenSearchCluster — the only opensearch.opster.io kind that
// directly owns a Pod (the bootstrap pod the operator runs before the first node
// pool comes up). The other kinds in this group (OpensearchRole, OpensearchUser,
// OpensearchTenant, OpensearchActionGroup, OpensearchUserRoleBinding,
// OpensearchIndexTemplate, OpensearchComponentTemplate, OpenSearchISMPolicy,
// OpensearchSnapshotPolicy) configure the OpenSearch API and own no workloads, so
// they are not registered.

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is the group version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: "opensearch.opster.io", Version: "v1"}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&OpenSearchCluster{},
		&OpenSearchClusterList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
