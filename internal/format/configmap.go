package format

import (
	"strings"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var archiveConfigMapKeySuffixes = []string{
	".7z",
	".bz2",
	".gz",
	".rar",
	".tar",
	".tar.bz2",
	".tar.gz",
	".tar.xz",
	".tar.zst",
	".tbz2",
	".tgz",
	".txz",
	".xz",
	".zip",
	".zst",
}

func FormatConfigMap(obj client.Object) client.Object {
	configMap, ok := obj.(*v1.ConfigMap)
	if !ok {
		return obj
	}

	configMap.BinaryData = nil

	for key := range configMap.Data {
		if isArchiveConfigMapKey(key) {
			delete(configMap.Data, key)
		}
	}

	return configMap
}

func isArchiveConfigMapKey(key string) bool {
	normalized := strings.ToLower(key)
	for _, suffix := range archiveConfigMapKeySuffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}
