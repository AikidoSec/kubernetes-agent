package transform

import (
	"encoding/json"
	"reflect"
	"testing"

	"aikidoSec.kubernetesAgent/pkg/models"
)

func ptr(s string) *string { return &s }

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid json %s: %v", b, err)
	}
	return m
}

func TestMarshal(t *testing.T) {
	labelRules := models.MetadataTransforms{Labels: map[string]models.KeyRule{
		"team":     {Rename: ptr("owner"), ValueMap: map[string]string{"platform-eng": "Platform Engineering"}},
		"internal": {Redact: true},
		"env":      {ValueMap: map[string]string{"prod": "production"}},
	}}
	meta := func(labels, annotations map[string]any) map[string]any {
		return map[string]any{"labels": labels, "annotations": annotations}
	}

	tests := []struct {
		name  string
		rules models.MetadataTransforms
		in    map[string]any
		want  map[string]any
	}{
		{
			name:  "value map, rename, redact and passthrough",
			rules: labelRules,
			in: map[string]any{"metadata": meta(map[string]any{
				"team": "platform-eng", "internal": "x", "env": "dev", "other": "keep",
			}, nil)},
			want: map[string]any{"metadata": meta(map[string]any{
				"owner": "Platform Engineering", "env": "dev", "other": "keep", "internal": redact("x"),
			}, nil)},
		},
		{
			name:  "unmatched value passes through renamed key",
			rules: labelRules,
			in:    map[string]any{"metadata": meta(map[string]any{"team": "other"}, nil)},
			want:  map[string]any{"metadata": meta(map[string]any{"owner": "other"}, nil)},
		},
		{
			name:  "rename collision: renamed entry wins",
			rules: labelRules,
			in:    map[string]any{"metadata": meta(map[string]any{"team": "a", "owner": "existing"}, nil)},
			want:  map[string]any{"metadata": meta(map[string]any{"owner": "a"}, nil)},
		},
		{
			name:  "labels rules do not touch annotations",
			rules: labelRules,
			in:    map[string]any{"metadata": meta(map[string]any{"env": "prod"}, map[string]any{"env": "prod", "internal": "x"})},
			want:  map[string]any{"metadata": meta(map[string]any{"env": "production"}, map[string]any{"env": "prod", "internal": "x"})},
		},
		{
			name:  "annotation rules do not touch labels",
			rules: models.MetadataTransforms{Annotations: map[string]models.KeyRule{"note": {Redact: true}}},
			in:    map[string]any{"metadata": meta(map[string]any{"note": "l"}, map[string]any{"note": "a", "k": "v"})},
			want:  map[string]any{"metadata": meta(map[string]any{"note": "l"}, map[string]any{"note": redact("a"), "k": "v"})},
		},
		{
			name:  "spec.template.metadata",
			rules: labelRules,
			in:    map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": meta(map[string]any{"internal": "x", "a": "b"}, nil)}}},
			want:  map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": meta(map[string]any{"a": "b", "internal": redact("x")}, nil)}}},
		},
		{
			name:  "spec.jobTemplate.metadata",
			rules: labelRules,
			in:    map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"metadata": meta(map[string]any{"internal": "x"}, nil)}}},
			want:  map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"metadata": meta(map[string]any{"internal": redact("x")}, nil)}}},
		},
		{
			name:  "spec.jobTemplate.spec.template.metadata",
			rules: labelRules,
			in: map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{
				"template": map[string]any{"metadata": meta(map[string]any{"env": "prod"}, nil)}}}}},
			want: map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{
				"template": map[string]any{"metadata": meta(map[string]any{"env": "production"}, nil)}}}}},
		},
		{
			name:  "spec.jobTargetRef.template.metadata",
			rules: labelRules,
			in: map[string]any{"spec": map[string]any{"jobTargetRef": map[string]any{
				"template": map[string]any{"metadata": meta(map[string]any{"env": "prod"}, nil)}}}},
			want: map[string]any{"spec": map[string]any{"jobTargetRef": map[string]any{
				"template": map[string]any{"metadata": meta(map[string]any{"env": "production"}, nil)}}}},
		},
		{
			name:  "spec.metadata",
			rules: labelRules,
			in:    map[string]any{"spec": map[string]any{"metadata": meta(map[string]any{"env": "prod"}, nil)}},
			want:  map[string]any{"spec": map[string]any{"metadata": meta(map[string]any{"env": "production"}, nil)}},
		},
		{
			name:  "rollout canary and blueGreen metadata",
			rules: labelRules,
			in: map[string]any{"spec": map[string]any{"strategy": map[string]any{
				"canary": map[string]any{
					"canaryMetadata": meta(map[string]any{"env": "prod"}, nil),
					"stableMetadata": meta(map[string]any{"internal": "x"}, nil),
				},
				"blueGreen": map[string]any{
					"previewMetadata": meta(map[string]any{"env": "prod"}, nil),
					"activeMetadata":  meta(map[string]any{"internal": "x"}, nil),
				}}}},
			want: map[string]any{"spec": map[string]any{"strategy": map[string]any{
				"canary": map[string]any{
					"canaryMetadata": meta(map[string]any{"env": "production"}, nil),
					"stableMetadata": meta(map[string]any{"internal": redact("x")}, nil),
				},
				"blueGreen": map[string]any{
					"previewMetadata": meta(map[string]any{"env": "production"}, nil),
					"activeMetadata":  meta(map[string]any{"internal": redact("x")}, nil),
				}}}},
		},
		{
			name:  "rollout experiment template metadata in every step and template",
			rules: labelRules,
			in: map[string]any{"spec": map[string]any{"strategy": map[string]any{"canary": map[string]any{"steps": []any{
				map[string]any{"setWeight": 10},
				map[string]any{"experiment": map[string]any{"templates": []any{
					map[string]any{"name": "a", "metadata": meta(map[string]any{"env": "prod"}, nil)},
					map[string]any{"name": "b", "metadata": meta(map[string]any{"keep": "k"}, nil)},
				}}},
				map[string]any{"experiment": map[string]any{"templates": []any{
					map[string]any{"name": "c", "metadata": meta(map[string]any{"internal": "x"}, nil)},
				}}},
			}}}}},
			want: map[string]any{"spec": map[string]any{"strategy": map[string]any{"canary": map[string]any{"steps": []any{
				map[string]any{"setWeight": 10},
				map[string]any{"experiment": map[string]any{"templates": []any{
					map[string]any{"name": "a", "metadata": meta(map[string]any{"env": "production"}, nil)},
					map[string]any{"name": "b", "metadata": meta(map[string]any{"keep": "k"}, nil)},
				}}},
				map[string]any{"experiment": map[string]any{"templates": []any{
					map[string]any{"name": "c", "metadata": meta(map[string]any{"internal": redact("x")}, nil)},
				}}},
			}}}}},
		},
		{
			name:  "service selector follows the label rules",
			rules: labelRules,
			in: map[string]any{"apiVersion": "v1", "kind": "Service", "spec": map[string]any{
				"selector": map[string]any{"team": "platform-eng", "internal": "x", "env": "prod", "keep": "k"}, "type": "ClusterIP"}},
			want: map[string]any{"apiVersion": "v1", "kind": "Service", "spec": map[string]any{
				"selector": map[string]any{"owner": "Platform Engineering", "internal": redact("x"), "env": "production", "keep": "k"}, "type": "ClusterIP"}},
		},
		{
			name:  "workload matchLabels follow the label rules",
			rules: labelRules,
			in: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "spec": map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"team": "platform-eng", "internal": "x", "keep": "k"}, "matchExpressions": []any{}},
				"template": map[string]any{"metadata": meta(map[string]any{"team": "platform-eng", "internal": "x", "keep": "k"}, nil)}}},
			want: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "spec": map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"owner": "Platform Engineering", "internal": redact("x"), "keep": "k"}, "matchExpressions": []any{}},
				"template": map[string]any{"metadata": meta(map[string]any{"owner": "Platform Engineering", "internal": redact("x"), "keep": "k"}, nil)}}},
		},
		{
			name:  "workload selector without matchLabels",
			rules: labelRules,
			in:    map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "spec": map[string]any{"selector": map[string]any{"matchExpressions": []any{}}}},
			want:  map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "spec": map[string]any{"selector": map[string]any{"matchExpressions": []any{}}}},
		},
		{
			name:  "selector of a non-Service object is untouched",
			rules: labelRules,
			in:    map[string]any{"apiVersion": "serving.knative.dev/v1", "kind": "Service", "spec": map[string]any{"selector": map[string]any{"env": "prod"}}},
			want:  map[string]any{"apiVersion": "serving.knative.dev/v1", "kind": "Service", "spec": map[string]any{"selector": map[string]any{"env": "prod"}}},
		},
		{
			name:  "service without selector",
			rules: labelRules,
			in:    map[string]any{"apiVersion": "v1", "kind": "Service", "spec": map[string]any{"type": "ExternalName"}},
			want:  map[string]any{"apiVersion": "v1", "kind": "Service", "spec": map[string]any{"type": "ExternalName"}},
		},
		{
			name:  "null and absent labels",
			rules: labelRules,
			in:    map[string]any{"metadata": map[string]any{"name": "x", "labels": nil}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{}}}},
			want:  map[string]any{"metadata": map[string]any{"name": "x", "labels": nil}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{}}}},
		},
		{
			name:  "no metadata paths present",
			rules: labelRules,
			in:    map[string]any{"data": "x"},
			want:  map[string]any{"data": "x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.rules).Marshal(tt.in)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			wantJSON, err := json.Marshal(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decode(t, got), decode(t, wantJSON)) {
				t.Errorf("Marshal() = %s, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalWithoutRulesMatchesJSONMarshal(t *testing.T) {
	obj := struct {
		Zeta     string         `json:"zeta"`
		Alpha    int64          `json:"alpha"`
		Metadata map[string]any `json:"metadata"`
	}{"z", 9007199254740993, map[string]any{"labels": map[string]string{"b": "1", "a": "2"}}}
	want, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	for name, tr := range map[string]*Transformer{
		"nil transformer": nil,
		"empty rules":     New(models.MetadataTransforms{}),
		"empty maps":      New(models.MetadataTransforms{Labels: map[string]models.KeyRule{}}),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := tr.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}

func TestMarshalPreservesLargeIntegers(t *testing.T) {
	tr := New(models.MetadataTransforms{Labels: map[string]models.KeyRule{"a": {Redact: true}}})
	in := json.RawMessage(`{"metadata":{"labels":{"a":"1","b":"2"}},"spec":{"big":9007199254740993}}`)

	got, err := tr.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"metadata":{"labels":{"a":"` + redact("1") + `","b":"2"}},"spec":{"big":9007199254740993}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestRedact(t *testing.T) {
	if got := redact("web"); len(got) != redactedLength || got != redact("web") {
		t.Errorf("redact(web) = %q, want a stable %d character value", got, redactedLength)
	}
	if redact("web") == redact("api") {
		t.Error("different values must redact differently")
	}
}

func TestRedactWithRenameKeepsRedactedValue(t *testing.T) {
	tr := New(models.MetadataTransforms{Labels: map[string]models.KeyRule{"app": {Rename: ptr("workload"), Redact: true}}})
	got, err := tr.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "web"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"metadata":{"labels":{"workload":"` + redact("web") + `"}}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
