package predicates

import (
	"maps"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewServicePredicate(nsFilter *NamespaceFilter) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.ObjectNew) && (HasStatusChanged(e) || IsSpecOrMetadataChanged(e))
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}

func HasStatusChanged(e event.UpdateEvent) bool {
	oldObj, ok := e.ObjectOld.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	newObj, ok := e.ObjectNew.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	oldStatusMap, _, err := unstructured.NestedMap(oldObj.Object, "status")
	if err != nil {
		return false
	}

	newStatusMap, _, err := unstructured.NestedMap(newObj.Object, "status")
	if err != nil {
		return false
	}

	return !maps.Equal(oldStatusMap, newStatusMap)
}
