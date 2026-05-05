package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewGatewayPredicate(nsFilter *NamespaceFilter) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.ObjectNew) && (IsSpecModified(e) || HasStatusChanged(e))
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}
