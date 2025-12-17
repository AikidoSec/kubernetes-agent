package models

import (
	"aikidoSec.kubernetesAgent/internal/predicates"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type WatcherSelector struct {
	schema.GroupVersionKind
	NamespaceExclusions *predicates.NamespaceExclusions
}
