package manager

import "testing"

func TestUpdateImageTag(t *testing.T) {
	tests := []struct {
		name   string
		image  string
		newTag string
		want   string
		wantOK bool
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
			name:   "registry with port and no tag is left alone",
			image:  "registry.example.com:5000/falcosecurity/falco",
			newTag: "0.44.0",
			wantOK: false,
		},
		{
			name:   "plain image with no tag is left alone",
			image:  "falco",
			newTag: "0.44.0",
			wantOK: false,
		},
		{
			name:   "digest-only reference is left alone",
			image:  "falcosecurity/falco@sha256:abc123",
			newTag: "0.44.0",
			wantOK: false,
		},
		{
			name:   "tag-and-digest reference is left alone",
			image:  "falcosecurity/falco:0.43.0@sha256:abc123",
			newTag: "0.44.0",
			wantOK: false,
		},
		{
			name:   "registry-port plus digest reference is left alone",
			image:  "registry.example.com:5000/falco:0.43.0@sha256:abc123",
			newTag: "0.44.0",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := updateImageTag(tt.image, tt.newTag)
			if ok != tt.wantOK {
				t.Fatalf("updateImageTag(%q, %q) ok = %v, want %v", tt.image, tt.newTag, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("updateImageTag(%q, %q) = %q, want %q", tt.image, tt.newTag, got, tt.want)
			}
		})
	}
}
