package predicates

import (
	"log"
	"reflect"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

			oldObj, err := endpointsFromUnstructured(e.ObjectOld)
			if err != nil {
				log.Println("error converting old object to Endpoints:", err)
				return false
			}

			newObj, err := endpointsFromUnstructured(e.ObjectNew)
			if err != nil {
				log.Println("error converting new object to Endpoints:", err)
				return false
			}

			// Compare subsets (addresses/ports)
			return !reflect.DeepEqual(oldObj.Subsets, newObj.Subsets)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}

func endpointsFromUnstructured(obj client.Object) (v1.Endpoints, error) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return v1.Endpoints{}, nil
	}

	var endpoints v1.Endpoints
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.UnstructuredContent(), &endpoints)
	if err != nil {
		return v1.Endpoints{}, err
	}

	return endpoints, nil
}
