package manager

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (s *Service) shouldCreateController(serverResourcesGVKs map[string]struct{}, gvk schema.GroupVersionKind, restMapper meta.RESTMapper, agentClusterRole *rbacv1.ClusterRole) (bool, error) {
	// Skip the GVK if it's not available in the cluster
	if _, found := serverResourcesGVKs[gvk.String()]; len(serverResourcesGVKs) > 0 && !found {
		s.logger.LogWarning(fmt.Errorf("GVK %s not found in cluster", gvk.String()), "skipping watcher setup")
		return false, nil
	}

	// Get the REST mapping for the GVK
	mapping, err := restMapper.RESTMapping(
		gvk.GroupKind(),
		gvk.Version,
	)
	if err != nil {
		return false, fmt.Errorf("error getting REST mapping for GVK (`%s`): %w", gvk.String(), err)
	}

	// Skip the GVK if the agent does not have the required permissions to watch it
	if !clusterRoleAllowsWatch(agentClusterRole, gvk.Group, mapping.Resource.Resource) {
		s.logger.LogWarning(fmt.Errorf("agent does not have permissions to watch resource %s", mapping.Resource.Resource), "skipping watcher setup")
		return false, nil
	}

	return true, nil
}

func clusterRoleAllowsWatch(role *rbacv1.ClusterRole, apiGroup, resource string) bool {
	if role == nil {
		return false
	}

	neededVerbs := map[string]bool{
		"get":   false,
		"list":  false,
		"watch": false,
	}

	for _, rule := range role.Rules {
		if !listMatchesValues(rule.APIGroups, apiGroup) {
			continue
		}

		if !listMatchesValues(rule.Resources, resource) {
			continue
		}

		isWildcardVerb := false
		for _, verb := range rule.Verbs {
			if verb == "*" {
				isWildcardVerb = true
				break
			}

			if _, ok := neededVerbs[verb]; ok {
				neededVerbs[verb] = true
			}
		}

		if isWildcardVerb {
			return true
		}

		verbsAllowed := true
		for _, hasVerb := range neededVerbs {
			if hasVerb {
				continue
			}

			verbsAllowed = false
			break
		}

		if verbsAllowed {
			return true
		}
	}

	return false
}

func listMatchesValues(list []string, val string) bool {
	for _, v := range list {
		if v == "*" || v == val {
			return true
		}
	}
	return false
}
