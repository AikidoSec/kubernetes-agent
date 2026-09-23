package predicates

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"

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
			return !nsFilter.IsObjectExcluded(e.ObjectNew) && IsSpecOrMetadataChanged(e)
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
		return NewTopLevelFieldsPredicate(nsFilter, "automountServiceAccountToken", "imagePullSecrets", "secrets")
	case "rbac.authorization.k8s.io/v1, Kind=Role", "rbac.authorization.k8s.io/v1, Kind=ClusterRole":
		return NewTopLevelFieldsPredicate(nsFilter, "rules", "aggregationRule")
	case "rbac.authorization.k8s.io/v1, Kind=RoleBinding", "rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding":
		return NewTopLevelFieldsPredicate(nsFilter, "subjects", "roleRef")
	case "/v1, Kind=Service", "networking.k8s.io/v1, Kind=Ingress",
		"route.openshift.io/v1, Kind=Route",
		"operator.openshift.io/v1, Kind=IngressController":
		return NewServicePredicate(nsFilter)
	case "/v1, Kind=Endpoints":
		return NewEndpointsPredicates(nsFilter)
	case "discovery.k8s.io/v1, Kind=EndpointSlice":
		return NewEndpointSlicePredicates(nsFilter)
	case "gateway.networking.k8s.io/v1, Kind=Gateway", "gateway.networking.k8s.io/v1, Kind=HTTPRoute":
		return NewGatewayPredicate(nsFilter)
	case "/v1, Kind=ConfigMap":
		return NewTopLevelFieldsPredicate(nsFilter, "data", "immutable")
	case "storage.k8s.io/v1, Kind=StorageClass":
		return NewTopLevelFieldsPredicate(nsFilter, "provisioner", "reclaimPolicy", "allowVolumeExpansion", "mountOptions", "volumeBindingMode", "parameters", "allowedTopologies")
	default:
		return NewGenericPredicate(nsFilter)
	}
}

func IsSpecOrMetadataChanged(e event.UpdateEvent) bool {
	return IsSpecModified(e) || AreAnnotationsChanged(e) || AreLabelsChanged(e)
}

// IsSpecModified checks if the resource spec has been modified based on the update event
func IsSpecModified(e event.UpdateEvent) bool {
	oldSpec, ok := specJSON(e.ObjectOld)
	if !ok {
		return false
	}

	newSpec, ok := specJSON(e.ObjectNew)
	if !ok {
		return false
	}

	return !bytes.Equal(oldSpec, newSpec)
}

// AreLabelsChanged checks if the resource labels has been modified based on the update event
func AreLabelsChanged(e event.UpdateEvent) bool {
	return !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
}

// AreAnnotationsChanged checks if the resource annotations has been modified based on the update event
func AreAnnotationsChanged(e event.UpdateEvent) bool {
	return !maps.Equal(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations())
}

// specJSON returns the JSON of an object's spec. For typed objects it marshals only the
// Spec field, avoiding a whole-object round-trip and keeping int64 values exact.
func specJSON(obj client.Object) ([]byte, bool) {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		spec, found, err := unstructured.NestedMap(u.Object, "spec")
		if err != nil || !found {
			return nil, false
		}
		b, err := json.Marshal(spec)
		if err != nil {
			return nil, false
		}
		return b, true
	}

	v := reflect.Indirect(reflect.ValueOf(obj))
	if v.Kind() != reflect.Struct {
		return nil, false
	}
	spec := v.FieldByName("Spec")
	if !spec.IsValid() || !spec.CanInterface() {
		return nil, false
	}
	b, err := json.Marshal(spec.Interface())
	if err != nil {
		return nil, false
	}
	return b, true
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
