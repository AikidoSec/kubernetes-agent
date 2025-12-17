package predicates

import (
	"reflect"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewEndpointsPredicates(nsExclusions *NamespaceExclusions) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if nsExclusions.IsObjectExcluded(e.ObjectNew) {
				return false
			}

			//nolint:staticcheck
			oldObj, ok := e.ObjectOld.(*v1.Endpoints)
			if !ok {
				return false
			}

			//nolint:staticcheck
			newObj, ok := e.ObjectNew.(*v1.Endpoints)
			if !ok {
				return false
			}

			// Compare subsets (addresses/ports)
			return !reflect.DeepEqual(oldObj.Subsets, newObj.Subsets)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
		},
	}
}
