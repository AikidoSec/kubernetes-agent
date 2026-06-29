package manager

import "testing"

func TestUpdateImageTag(t *testing.T) {
	tests := []struct {
		name   string
		image  string
		newTag string
		want   string
	}{
		{
			name:   "plain image with tag",
			image:  "falco:0.43.0",
			newTag: "0.44.0",
			want:   "falco:0.44.0",
		},
		{
			name:   "org/repo with tag",
			image:  "falcosecurity/falco:0.43.0",
			newTag: "0.44.0",
			want:   "falcosecurity/falco:0.44.0",
		},
		{
			name:   "registry with port and tag",
			image:  "registry.example.com:5000/falco:0.43.0",
			newTag: "0.44.0",
			want:   "registry.example.com:5000/falco:0.44.0",
		},
		{
			name:   "registry with port, nested path, and tag",
			image:  "registry.example.com:5000/falcosecurity/falco:0.43.0",
			newTag: "0.44.0",
			want:   "registry.example.com:5000/falcosecurity/falco:0.44.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateImageTag(tt.image, tt.newTag)
			if got != tt.want {
				t.Errorf("updateImageTag(%q, %q) = %q, want %q", tt.image, tt.newTag, got, tt.want)
			}
		})
	}
}
