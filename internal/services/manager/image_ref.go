package manager

import "strings"

func isDigestPinnedImage(image string) bool {
	return strings.Contains(image, "@")
}

// updateImageTag rewrites the tag portion of a tagged image reference like
// "falcosecurity/falco:0.43.0". Digest-pinned and untagged references are left
// unchanged and return false so callers can skip tag-based auto-updates.
func updateImageTag(image, newTag string) (string, bool) {
	if isDigestPinnedImage(image) {
		return image, false
	}

	lastColon := strings.LastIndex(image, ":")
	lastSlash := strings.LastIndex(image, "/")
	if lastColon <= lastSlash {
		return image, false
	}

	return image[:lastColon] + ":" + newTag, true
}
