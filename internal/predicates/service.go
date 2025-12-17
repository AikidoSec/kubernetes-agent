package predicates

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewServicePredicate(nsExclusions *NamespaceExclusions) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.ObjectNew) && (HasStatusChanged(e) || IsSpecModified(e))
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
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

	oldStatusMap, found, err := unstructured.NestedMap(oldObj.Object, "status")
	if err != nil || !found {
		return false
	}

	newStatusMap, found, err := unstructured.NestedMap(newObj.Object, "status")
	if err != nil || !found {
		return false
	}

	oldStatus, err := json.Marshal(oldStatusMap)
	if err != nil {
		return false
	}

	newStatus, err := json.Marshal(newStatusMap)
	if err != nil {
		return false
	}

	return string(oldStatus) != string(newStatus)
}
