package predicates

import (
	"reflect"

	v1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewEndpointSlicePredicates(excludedNamespaces []string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if IsObjectFromExcludedNamespace(e.ObjectNew, excludedNamespaces) {
				return false
			}

			oldObj, ok := e.ObjectOld.(*v1.EndpointSlice)
			if !ok {
				return false
			}

			newObj, ok := e.ObjectNew.(*v1.EndpointSlice)
			if !ok {
				return false
			}

			// Trigger reconcile if the endpoints changed
			if !reflect.DeepEqual(oldObj.Endpoints, newObj.Endpoints) {
				return true
			}
			// Trigger reconcile if the ports changed
			if !reflect.DeepEqual(oldObj.Ports, newObj.Ports) {
				return true
			}
			
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
	}
}
