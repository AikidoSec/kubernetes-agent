package predicates

import (
	"encoding/json"

	"github.com/gobwas/glob"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewGenericPredicate(nsFilter *NamespaceFilter) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !nsFilter.IsObjectExcluded(e.ObjectNew) && IsSpecModified(e)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !nsFilter.IsObjectExcluded(e.Object)
		},
	}
}

func GetPredicatesForGVK(gvk string, nsFilter *NamespaceFilter) predicate.Predicate {
	switch gvk {
	case "/v1, Kind=Pod":
		return NewPodPredicate(nsFilter)
	case "/v1, Kind=ServiceAccount":
		return NewServiceAccountPredicate(nsFilter)
	case "/v1, Kind=Service", "networking.k8s.io/v1, Kind=Ingress":
		return NewServicePredicate(nsFilter)
	case "/v1, Kind=Endpoints":
		return NewEndpointsPredicates(nsFilter)
	case "discovery.k8s.io/v1, Kind=EndpointSlice":
		return NewEndpointSlicePredicates(nsFilter)
	default:
		return NewGenericPredicate(nsFilter)
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

type NamespaceFilter struct {
	excludePatterns []glob.Glob
	includePatterns []glob.Glob
}

type logger interface {
	LogWarning(err error, message string, args ...any)
}

func NewNamespaceFilter(logger logger, excludedNamespaces, includedNamespaces []string) *NamespaceFilter {
	excludePatterns := compilePatterns(logger, excludedNamespaces, "exclusion")
	includePatterns := compilePatterns(logger, includedNamespaces, "inclusion")
	return &NamespaceFilter{excludePatterns: excludePatterns, includePatterns: includePatterns}
}

func compilePatterns(logger logger, namespaces []string, label string) []glob.Glob {
	patterns := make([]glob.Glob, 0, len(namespaces))
	for _, pattern := range namespaces {
		compiled, err := glob.Compile(pattern)
		if err != nil {
			logger.LogWarning(err, "Namespace %s could not be parsed and will be ignored: %q", label, pattern)
		} else {
			patterns = append(patterns, compiled)
		}
	}
	return patterns
}

func (n *NamespaceFilter) IsObjectExcluded(o client.Object) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}
	return n.IsExcluded(ns)
}

func (n *NamespaceFilter) IsExcluded(namespace string) bool {
	if len(n.includePatterns) > 0 {
		for _, pattern := range n.includePatterns {
			if pattern.Match(namespace) {
				return false
			}
		}
		return true
	}

	for _, pattern := range n.excludePatterns {
		if pattern.Match(namespace) {
			return true
		}
	}
	return false
}
