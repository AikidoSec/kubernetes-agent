package predicates

import (
	"encoding/json"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewGenericPredicate(excludedNamespaces []string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if IsObjectFromExcludedNamespace(e.ObjectNew, excludedNamespaces) {
				return false
			}

			return IsSpecModified(e)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
	}
}

func GetPredicatesForGVK(gvk string, excludedNamespaces []string) predicate.Predicate {
	switch gvk {
	case "/v1, Kind=Pod":
		return NewPodPredicate(excludedNamespaces)
	case "/v1, Kind=ServiceAccount":
		return NewServiceAccountPredicate(excludedNamespaces)
	case "/v1, Kind=Service", "networking.k8s.io/v1, Kind=Ingress":
		return NewServicePredicate(excludedNamespaces)
	case "/v1, Kind=Endpoints":
		return NewEndpointsPredicates(excludedNamespaces)
	case "discovery.k8s.io/v1, Kind=EndpointSlice":
		return NewEndpointSlicePredicates(excludedNamespaces)
	default:
		return NewGenericPredicate(excludedNamespaces)
	}
}

// IsSpecModified checks if the resource spec has been modified based on the update event
func IsSpecModified(e event.UpdateEvent) bool {
	oldObj, ok := e.ObjectOld.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	newObj, ok := e.ObjectNew.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	oldSpecMap, found, err := unstructured.NestedMap(oldObj.Object, "spec")
	if err != nil || !found {
		return false
	}

	newSpecMap, found, err := unstructured.NestedMap(newObj.Object, "spec")
	if err != nil || !found {
		return false
	}

	oldSpec, err := json.Marshal(oldSpecMap)
	if err != nil {
		return false
	}

	newSpec, err := json.Marshal(newSpecMap)
	if err != nil {
		return false
	}

	return string(oldSpec) != string(newSpec)
}

// IsObjectFromExcludedNamespace checks if the object is from an excluded namespace
func IsObjectFromExcludedNamespace(o client.Object, excludedNamespaces []string) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}

	return slices.Contains(excludedNamespaces, ns)
}
