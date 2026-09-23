package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewServiceAccountPredicate(nsFilter *NamespaceFilter) predicate.Predicate {
	return NewTopLevelFieldsPredicate(nsFilter, "automountServiceAccountToken", "imagePullSecrets", "secrets")
}
