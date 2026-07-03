package manager

import "testing"

func TestUpdateImageTag(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		newTag  string
		want    string
		wantOK  bool
	}{
		{
			name:   "plain image with tag",
			image:  "falco:0.43.0",
			newTag: "0.44.0",
			want:   "falco:0.44.0",
			wantOK: true,
		},
		{
			name:   "org/repo with tag",
			image:  "falcosecurity/falco:0.43.0",
			newTag: "0.44.0",
			want:   "falcosecurity/falco:0.44.0",
			wantOK: true,
		},
		{
			name:   "registry with port and tag",
			image:  "registry.example.com:5000/falco:0.43.0",
			newTag: "0.44.0",
			want:   "registry.example.com:5000/falco:0.44.0",
			wantOK: true,
		},
		{
			name:   "registry with port, nested path, and tag",
			image:  "registry.example.com:5000/falcosecurity/falco:0.43.0",
			newTag: "0.44.0",
			want:   "registry.example.com:5000/falcosecurity/falco:0.44.0",
			wantOK: true,
		},
		{
			name:   "digest-pinned image is not rewritten",
			image:  "falcosecurity/falco@sha256:0123456789abcdef",
			newTag: "0.44.0",
			want:   "falcosecurity/falco@sha256:0123456789abcdef",
			wantOK: false,
		},
		{
			name:   "untagged image is not rewritten",
			image:  "falcosecurity/falco",
			newTag: "0.44.0",
			want:   "falcosecurity/falco",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := updateImageTag(tt.image, tt.newTag)
			if got != tt.want {
				t.Errorf("updateImageTag(%q, %q) = %q, want %q", tt.image, tt.newTag, got, tt.want)
			}
			if ok != tt.wantOK {
				t.Errorf("updateImageTag(%q, %q) ok = %v, want %v", tt.image, tt.newTag, ok, tt.wantOK)
			}
		})
	}
}
