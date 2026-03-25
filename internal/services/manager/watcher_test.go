package manager

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestListMatchesValues(t *testing.T) {
	tests := []struct {
		name     string
		list     []string
		val      string
		expected bool
	}{
		{"exact match", []string{"pods", "deployments"}, "pods", true},
		{"wildcard match", []string{"*"}, "anything", true},
		{"no match", []string{"pods", "deployments"}, "secrets", false},
		{"empty list", []string{}, "pods", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listMatchesValues(tt.list, tt.val); got != tt.expected {
				t.Errorf("listMatchesValues(%v, %q) = %v, want %v", tt.list, tt.val, got, tt.expected)
			}
		})
	}
}

func TestClusterRoleAllowsWatch(t *testing.T) {
	rule := func(apiGroups, resources, verbs []string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: apiGroups, Resources: resources, Verbs: verbs}
	}

	role := func(rules ...rbacv1.PolicyRule) *rbacv1.ClusterRole {
		return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "test"}, Rules: rules}
	}

	tests := []struct {
		name      string
		role      *rbacv1.ClusterRole
		apiGroup  string
		resource  string
		expected  bool
	}{
		{
			"nil role",
			nil, "", "", false,
		},
		{
			"all three verbs present",
			role(rule([]string{""}, []string{"pods"}, []string{"get", "list", "watch"})),
			"", "pods", true,
		},
		{
			"wildcard verb",
			role(rule([]string{""}, []string{"pods"}, []string{"*"})),
			"", "pods", true,
		},
		{
			"wildcard resource",
			role(rule([]string{""}, []string{"*"}, []string{"get", "list", "watch"})),
			"", "pods", true,
		},
		{
			"wildcard api group",
			role(rule([]string{"*"}, []string{"pods"}, []string{"get", "list", "watch"})),
			"apps", "pods", true,
		},
		{
			"missing watch verb",
			role(rule([]string{""}, []string{"pods"}, []string{"get", "list"})),
			"", "pods", false,
		},
		{
			"wrong resource",
			role(rule([]string{""}, []string{"deployments"}, []string{"get", "list", "watch"})),
			"", "pods", false,
		},
		{
			"wrong api group",
			role(rule([]string{"apps"}, []string{"pods"}, []string{"get", "list", "watch"})),
			"", "pods", false,
		},
		{
			"verbs split across two rules",
			role(
				rule([]string{""}, []string{"pods"}, []string{"get", "list"}),
				rule([]string{""}, []string{"pods"}, []string{"watch"}),
			),
			"", "pods", true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clusterRoleAllowsWatch(tt.role, tt.apiGroup, tt.resource); got != tt.expected {
				t.Errorf("clusterRoleAllowsWatch(%q, %q) = %v, want %v", tt.apiGroup, tt.resource, got, tt.expected)
			}
		})
	}
}
