package format

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

func FormatObject(obj *unstructured.Unstructured) *unstructured.Unstructured {
	switch obj.GroupVersionKind().String() {
	case "/v1, Kind=Secret":
		return formatSecret(obj)
	default:
		return obj
	}
}

func formatSecret(obj *unstructured.Unstructured) *unstructured.Unstructured {
	// Create a deep copy of the original object to avoid modifying it directly
	formattedObj := obj.DeepCopy()

	// Redact all data from the secret
	data, ok := formattedObj.Object["data"].(map[string]interface{})
	if !ok {
		formattedObj.Object["data"] = map[string]interface{}{}
	}
	for k := range data {
		data[k] = ""
	}

	return formattedObj
}
