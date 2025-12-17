package predicates

import (
	"encoding/json"

	"github.com/gobwas/glob"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewGenericPredicate(nsExclusions *NamespaceExclusions) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.ObjectNew) && IsSpecModified(e)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsExclusions.IsObjectExcluded(e.Object)
		},
	}
}

func GetPredicatesForGVK(gvk string, nsExclusions *NamespaceExclusions) predicate.Predicate {
	switch gvk {
	case "/v1, Kind=Pod":
		return NewPodPredicate(nsExclusions)
	case "/v1, Kind=ServiceAccount":
		return NewServiceAccountPredicate(nsExclusions)
	case "/v1, Kind=Service", "networking.k8s.io/v1, Kind=Ingress":
		return NewServicePredicate(nsExclusions)
	case "/v1, Kind=Endpoints":
		return NewEndpointsPredicates(nsExclusions)
	case "discovery.k8s.io/v1, Kind=EndpointSlice":
		return NewEndpointSlicePredicates(nsExclusions)
	default:
		return NewGenericPredicate(nsExclusions)
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

type NamespaceExclusions struct {
	patterns []glob.Glob
}

type logger interface {
	LogWarning(err error, message string, args ...any)
}

func NewNamespaceExclusions(logger logger, excludedNamespaces []string) *NamespaceExclusions {
	patterns := make([]glob.Glob, 0, len(excludedNamespaces))
	for _, pattern := range excludedNamespaces {
		glob, err := glob.Compile(pattern)
		if err != nil {
			logger.LogWarning(err, "Namespace exclusion could not be parsed and will be ignored: %q", pattern)
		} else {
			patterns = append(patterns, glob)
		}
	}
	return &NamespaceExclusions{patterns: patterns}
}

func (n *NamespaceExclusions) IsObjectExcluded(o client.Object) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}
	return n.IsExcluded(ns)
}

func (n *NamespaceExclusions) IsExcluded(namespace string) bool {
	for _, pattern := range n.patterns {
		if pattern.Match(namespace) {
			return true
		}
	}
	return false
}
