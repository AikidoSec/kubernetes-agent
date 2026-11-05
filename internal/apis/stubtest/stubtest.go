// Package stubtest holds the checks every stub under internal/apis must pass. They
// decode through the scheme's JSON serializer, the same one the informer ends in.
package stubtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Kind describes one stubbed kind: its GVK, constructors for the object and its list,
// and the function that registers it in a scheme.
type Kind struct {
	GVK     schema.GroupVersionKind
	Object  func() client.Object
	List    func() client.ObjectList
	Install func(*runtime.Scheme) error
}

// Run verifies that kind is registered, that spec and status reach the payload byte for
// byte whatever schema they carry, and that copies do not share memory.
func Run(t *testing.T, kind Kind) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := kind.Install(scheme); err != nil {
		t.Fatalf("registering %s: %v", kind.GVK, err)
	}
	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()

	t.Run("registered", func(t *testing.T) { registered(t, scheme, kind) })
	t.Run("forwards spec and status verbatim", func(t *testing.T) { forwardsVerbatim(t, decoder, kind) })
	t.Run("omits absent spec and status", func(t *testing.T) { omitsAbsent(t, decoder, kind) })
	t.Run("decodes a list with drifted items", func(t *testing.T) { decodesDriftedList(t, decoder, kind) })
	t.Run("deep copy does not alias", func(t *testing.T) { deepCopyIndependent(t, decoder, kind) })
	t.Run("list deep copy does not alias", func(t *testing.T) { listDeepCopyIndependent(t, decoder, kind) })
}

func registered(t *testing.T, scheme *runtime.Scheme, kind Kind) {
	listGVK := kind.GVK.GroupVersion().WithKind(kind.GVK.Kind + "List")

	for gvk, object := range map[schema.GroupVersionKind]runtime.Object{
		kind.GVK: kind.Object(),
		listGVK:  kind.List(),
	} {
		kinds, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Fatalf("resolving kind for %T: %v", object, err)
		}
		if len(kinds) != 1 || kinds[0] != gvk {
			t.Errorf("%T registered as %v, want %s", object, kinds, gvk)
		}

		created, err := scheme.New(gvk)
		if err != nil {
			t.Fatalf("scheme cannot create %s: %v", gvk, err)
		}
		if got, want := fmt.Sprintf("%T", created), fmt.Sprintf("%T", object); got != want {
			t.Errorf("scheme creates %s for %s, want %s", got, gvk, want)
		}
	}
}

// Fields no upstream version declares, a value whose type differs between versions, and
// an integer above 2^53: none of them may be lost, changed or fail the decode.
const (
	driftedSpec   = `{"futureField":{"nested":[1,"two",true,null]},"replicas":"three","bigNumber":9007199254740993}`
	driftedStatus = `{"failures":{"runner-a":true,"runner-b":"2024-12-12T10:40:00Z"},"conditions":[{"type":"Ready"}]}`
)

func objectJSON(kind Kind, name, body string) []byte {
	return []byte(`{"apiVersion":"` + kind.GVK.GroupVersion().String() + `","kind":"` + kind.GVK.Kind + `",` +
		`"metadata":{"name":"` + name + `","namespace":"default","labels":{"app":"demo"}}` + body + `}`)
}

func decode(t *testing.T, decoder runtime.Decoder, data []byte, into runtime.Object) {
	t.Helper()
	if _, _, err := decoder.Decode(data, nil, into); err != nil {
		t.Fatalf("decoding through the scheme codec: %v", err)
	}
}

func forwardsVerbatim(t *testing.T, decoder runtime.Decoder, kind Kind) {
	object := kind.Object()
	decode(t, decoder, objectJSON(kind, "drifted", `,"spec":`+driftedSpec+`,"status":`+driftedStatus), object)

	if object.GetName() != "drifted" || object.GetNamespace() != "default" || object.GetLabels()["app"] != "demo" {
		t.Errorf("metadata not decoded: name=%q namespace=%q labels=%v",
			object.GetName(), object.GetNamespace(), object.GetLabels())
	}

	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	for _, want := range []string{`"spec":` + driftedSpec, `"status":` + driftedStatus} {
		if !bytes.Contains(payload, []byte(want)) {
			t.Errorf("payload does not carry %s verbatim\ngot: %s", want, payload)
		}
	}
}

func omitsAbsent(t *testing.T, decoder runtime.Decoder, kind Kind) {
	for name, body := range map[string]string{
		"absent": ``,
		"null":   `,"spec":null,"status":null`,
	} {
		t.Run(name, func(t *testing.T) {
			object := kind.Object()
			decode(t, decoder, objectJSON(kind, "bare", body), object)

			payload, err := json.Marshal(object)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if strings.Contains(string(payload), `"spec"`) || strings.Contains(string(payload), `"status"`) {
				t.Errorf("payload invents spec or status the server did not send: %s", payload)
			}
		})
	}
}

// One undecodable item fails the informer's whole LIST, so every item must decode
// however its schema differs from its neighbours.
func decodesDriftedList(t *testing.T, decoder runtime.Decoder, kind Kind) {
	result := kind.List()
	decode(t, decoder, driftedListJSON(kind), result)

	if result.GetResourceVersion() != "42" {
		t.Errorf("list metadata not decoded: resourceVersion=%q", result.GetResourceVersion())
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshalling list: %v", err)
	}
	for _, want := range []string{`"name":"current"`, `"name":"legacy"`, `"value":"one"`, `"failures":{"b":true}`} {
		if !bytes.Contains(payload, []byte(want)) {
			t.Errorf("list lost %s\ngot: %s", want, payload)
		}
	}
}

func driftedListJSON(kind Kind) []byte {
	return []byte(`{"apiVersion":"` + kind.GVK.GroupVersion().String() + `","kind":"` + kind.GVK.Kind + `List",` +
		`"metadata":{"resourceVersion":"42"},"items":[` +
		string(objectJSON(kind, "current", `,"spec":{"value":1},"status":{"failures":{"a":"2024-12-12T10:40:00Z"}}`)) + `,` +
		string(objectJSON(kind, "legacy", `,"spec":{"value":"one"},"status":{"failures":{"b":true}}`)) + `]}`)
}

// The cache hands every reader its own copy, so a reconcile that changes the copy's
// metadata, or replaces its spec or status bytes (the format scrubbers do), must not
// reach the cached object.
func deepCopyIndependent(t *testing.T, decoder runtime.Decoder, kind Kind) {
	original := kind.Object()
	decode(t, decoder, objectJSON(kind, "copied", `,"spec":`+driftedSpec+`,"status":`+driftedStatus), original)

	before, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling original: %v", err)
	}

	copied, ok := original.DeepCopyObject().(client.Object)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, not a client.Object", original.DeepCopyObject())
	}
	if got, want := fmt.Sprintf("%T", copied), fmt.Sprintf("%T", original); got != want {
		t.Fatalf("DeepCopyObject returned %s, want %s", got, want)
	}

	afterCopy, err := json.Marshal(copied)
	if err != nil {
		t.Fatalf("marshalling copy: %v", err)
	}
	if !bytes.Equal(before, afterCopy) {
		t.Errorf("deep copy changed the payload\nwant: %s\ngot:  %s", before, afterCopy)
	}

	scribble(t, copied)
	copied.GetLabels()["app"] = "changed"

	after, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling original after mutating the copy: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("mutating the copy reached the original\nwant: %s\ngot:  %s", before, after)
	}
}

// The informer's initial LIST is cached item by item, so a list copy must not share
// any item's metadata or bytes with the original either.
func listDeepCopyIndependent(t *testing.T, decoder runtime.Decoder, kind Kind) {
	original := kind.List()
	decode(t, decoder, driftedListJSON(kind), original)

	before, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling original list: %v", err)
	}

	copied, ok := original.DeepCopyObject().(client.ObjectList)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, not a client.ObjectList", original.DeepCopyObject())
	}
	if got, want := fmt.Sprintf("%T", copied), fmt.Sprintf("%T", original); got != want {
		t.Fatalf("DeepCopyObject returned %s, want %s", got, want)
	}

	items := reflect.Indirect(reflect.ValueOf(copied)).FieldByName("Items")
	if items.Len() != 2 {
		t.Fatalf("copied list has %d items, want 2", items.Len())
	}
	for i := range items.Len() {
		item, ok := items.Index(i).Addr().Interface().(client.Object)
		if !ok {
			t.Fatalf("list item %d is not a client.Object", i)
		}
		scribble(t, item)
		item.GetLabels()["app"] = "changed"
	}

	after, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling original list after mutating the copy: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("mutating the list copy reached the original\nwant: %s\ngot:  %s", before, after)
	}
}

// scribble overwrites every byte of the copy's spec and status in place.
func scribble(t *testing.T, object client.Object) {
	t.Helper()
	value := reflect.Indirect(reflect.ValueOf(object))
	for _, name := range []string{"Spec", "Status"} {
		raw, ok := value.FieldByName(name).Addr().Interface().(*runtime.RawExtension)
		if !ok {
			t.Fatalf("%T.%s is not a runtime.RawExtension", object, name)
		}
		if len(raw.Raw) == 0 {
			t.Fatalf("%T.%s is empty, nothing to scribble on", object, name)
		}
		for i := range raw.Raw {
			raw.Raw[i] = 'X'
		}
	}
}
