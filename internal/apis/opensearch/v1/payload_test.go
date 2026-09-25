package v1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	opensearchv1 "aikidoSec.kubernetesAgent/internal/apis/opensearch/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	goldenPayload = "opensearchcluster_upstream_payload.json"
	zeroPayload   = "opensearchcluster_zero_payload.json"
)

// TestOpenSearchClusterPayloadMatchesUpstream guards the mirrored OpenSearchCluster
// type. The golden was produced by the upstream type at opensearch-k8s-operator
// v2.8.0, and the agent ships this payload verbatim as AssetPayload.Metadata, so a
// diff here changes what the backend receives. On a failure fix the mirrored struct;
// never edit the golden.
func TestOpenSearchClusterPayloadMatchesUpstream(t *testing.T) {
	expected := readGolden(t)
	var cluster opensearchv1.OpenSearchCluster
	if err := json.Unmarshal(expected, &cluster); err != nil {
		t.Fatalf("decoding golden into mirrored type: %v", err)
	}
	actual, err := json.Marshal(&cluster)
	if err != nil {
		t.Fatalf("marshalling mirrored type: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
	}
}

// TestZeroValuePayloadMatchesUpstream covers the one class of divergence the populated
// golden cannot show: an omitempty the mirror added or dropped is invisible while the
// field holds a non-zero value, because both sides then print it the same way. An
// empty cluster prints exactly the fields that lack omitempty, so the difference shows.
func TestZeroValuePayloadMatchesUpstream(t *testing.T) {
	expected := readPayload(t, zeroPayload)
	actual, err := json.Marshal(&opensearchv1.OpenSearchCluster{})
	if err != nil {
		t.Fatalf("marshalling zero value: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("zero-value payload diverged from upstream\nwant: %s\ngot:  %s", expected, actual)
	}
}

// TestDeepCopyPreservesPayload guards the copied deepcopy functions: controller-runtime's
// cache hands the same object to every listener, so a shallow copy would let one
// reconcile mutate another's view.
func TestDeepCopyPreservesPayload(t *testing.T) {
	expected := readGolden(t)
	var cluster opensearchv1.OpenSearchCluster
	if err := json.Unmarshal(expected, &cluster); err != nil {
		t.Fatalf("decoding golden: %v", err)
	}
	copied := cluster.DeepCopy()
	actual, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if string(expected) != string(actual) {
		t.Errorf("deep copy lost data\nwant: %s\ngot:  %s", expected, actual)
	}
	copied.Labels["mutated"] = "true"
	unchanged, err := json.Marshal(&cluster)
	if err != nil {
		t.Fatalf("re-marshalling original: %v", err)
	}
	if string(expected) != string(unchanged) {
		t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", expected, unchanged)
	}
}

// TestSchemeRegistration covers startup: a kind missing from the scheme fails the
// watch at runtime, not at compile time.
func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := opensearchv1.AddToScheme(scheme); err != nil {
		t.Fatalf("registering opensearch types: %v", err)
	}
	for _, object := range []runtime.Object{&opensearchv1.OpenSearchCluster{}, &opensearchv1.OpenSearchClusterList{}} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if got := kinds[0].GroupVersion(); got != opensearchv1.SchemeGroupVersion {
			t.Errorf("%T registered under %s, want %s", object, got, opensearchv1.SchemeGroupVersion)
		}
	}
}

// TestGoldenCoversEveryMirroredField keeps the payload test honest. A field whose
// value is absent from the golden is a field whose mirrored json tag is never
// compared against upstream, so a typo in it would pass unnoticed — which is easy to
// hit, because an omitempty scalar only appears once it holds a non-zero value.
func TestGoldenCoversEveryMirroredField(t *testing.T) {
	present := jsonKeys(t, readGolden(t))

	var missing []string
	for name := range mirroredFieldNames(reflect.TypeOf(opensearchv1.OpenSearchCluster{})) {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("golden never exercises %d mirrored field(s), regenerate it from upstream: %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// mirroredFieldNames returns the json names of every struct declared in this package
// that is reachable from root. Foreign types (corev1, metav1) are not mirrored, so
// their fields are out of scope.
func mirroredFieldNames(root reflect.Type) map[string]bool {
	pkg := root.PkgPath()
	names := map[string]bool{}
	seen := map[reflect.Type]bool{}

	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || t.PkgPath() != pkg || seen[t] {
			return
		}
		seen[t] = true
		for i := range t.NumField() {
			field := t.Field(i)
			if name := strings.Split(field.Tag.Get("json"), ",")[0]; name != "" && name != "-" {
				names[name] = true
			}
			walk(field.Type)
		}
	}
	walk(root)
	return names
}

// jsonKeys collects every object key appearing anywhere in the payload.
func jsonKeys(t *testing.T, payload []byte) map[string]bool {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decoding golden: %v", err)
	}

	keys := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for key, value := range n {
				keys[key] = true
				walk(value)
			}
		case []any:
			for _, value := range n {
				walk(value)
			}
		}
	}
	walk(decoded)
	return keys
}

func readGolden(t *testing.T) []byte {
	t.Helper()
	return readPayload(t, goldenPayload)
}

func readPayload(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading golden payload %s: %v", name, err)
	}
	return payload
}
