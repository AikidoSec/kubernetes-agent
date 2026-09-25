package predicates

import (
	"log"
	"reflect"

	v1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewEndpointSlicePredicates(nsFilter *NamespaceFilter) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if nsFilter.IsObjectExcluded(e.ObjectNew) {
				return false
			}

			oldObj, err := endpointSliceFromUnstructured(e.ObjectOld)
			if err != nil {
				log.Println("error converting old object to EndpointSlice:", err)
				return false
			}

			newObj, err := endpointSliceFromUnstructured(e.ObjectNew)
			if err != nil {
				log.Println("error converting new object to EndpointSlice:", err)
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
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}

func endpointSliceFromUnstructured(obj client.Object) (v1.EndpointSlice, error) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return v1.EndpointSlice{}, nil
	}

	var endpoints v1.EndpointSlice
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.UnstructuredContent(), &endpoints)
	if err != nil {
		return v1.EndpointSlice{}, err
	}

	return endpoints, nil
}
