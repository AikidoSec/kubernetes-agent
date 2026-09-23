package predicates

import (
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewEndpointsPredicates(nsFilter *NamespaceFilter) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if nsFilter.IsObjectExcluded(e.ObjectNew) {
				return false
			}

			oldObject, ok := e.ObjectOld.(*unstructured.Unstructured)
			if !ok {
				return false
			}

			newObject, ok := e.ObjectNew.(*unstructured.Unstructured)
			if !ok {
				return false
			}

			// Compare subsets (addresses/ports)
			return !reflect.DeepEqual(oldObject.Object["subsets"], newObject.Object["subsets"])
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}
