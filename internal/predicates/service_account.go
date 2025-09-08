package predicates

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewServiceAccountPredicate(excludedNamespaces []string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if IsObjectFromExcludedNamespace(e.ObjectNew, excludedNamespaces) {
				return false
			}

			return AreAnnotationsChanged(e)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
	}
}

// AreAnnotationsChanged checks if the annotations of the old and new objects in the update event are different.
func AreAnnotationsChanged(e event.UpdateEvent) bool {
	oldObj, ok := e.ObjectOld.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	newObj, ok := e.ObjectNew.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	oldAnnotationsMap, found, err := unstructured.NestedMap(oldObj.Object, "metadata", "annotations")
	if err != nil || !found {
		return false
	}

	newAnnotationsMap, found, err := unstructured.NestedMap(newObj.Object, "metadata", "annotations")
	if err != nil || !found {
		return false
	}

	// Serialize the 'metadata.annotations' maps to JSON for comparison
	oldAnnotations, err := json.Marshal(oldAnnotationsMap)
	if err != nil {
		return false
	}

	newAnnotations, err := json.Marshal(newAnnotationsMap)
	if err != nil {
		return false
	}

	return string(oldAnnotations) != string(newAnnotations)
}
