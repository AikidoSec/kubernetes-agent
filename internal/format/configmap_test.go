package format_test

import (
	"testing"

	"aikidoSec.kubernetesAgent/internal/format"
	v1 "k8s.io/api/core/v1"
)

func TestFormatConfigMapRemovesBinaryDataAndArchiveDataKeys(t *testing.T) {
	configMap := &v1.ConfigMap{
		Data: map[string]string{
			"archive.tar":     "tar content",
			"chart.TGZ":       "chart content",
			"bundle.tar.gz":   "compressed tar content",
			"metadata.json":   "{}",
			"application.yml": "enabled: true",
		},
		BinaryData: map[string][]byte{
			"payload": []byte("binary content"),
		},
	}

	formatted := format.FormatConfigMap(configMap)

	got, ok := formatted.(*v1.ConfigMap)
	if !ok {
		t.Fatalf("FormatConfigMap returned %T, want *v1.ConfigMap", formatted)
	}

	if got.BinaryData != nil {
		t.Errorf("BinaryData = %v, want nil", got.BinaryData)
	}

	for _, key := range []string{"archive.tar", "chart.TGZ", "bundle.tar.gz"} {
		if _, ok := got.Data[key]; ok {
			t.Errorf("Data[%q] was not removed", key)
		}
	}

	for _, key := range []string{"metadata.json", "application.yml"} {
		if _, ok := got.Data[key]; !ok {
			t.Errorf("Data[%q] was removed unexpectedly", key)
		}
	}
}
