package config

import "testing"

func TestDeriveRuntimeDetectionEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		apiEndpoint string
		want        string
		wantErr     bool
	}{
		{
			name:        "prod eu (default, no region segment)",
			apiEndpoint: "https://k8s.aikido-security.com",
			want:        "https://endpoint-server-ingest.aikido.dev",
		},
		{
			name:        "staging (single shared region)",
			apiEndpoint: "https://k8s.staging.aikido-security.com",
			want:        "https://endpoint-server-ingest.test.aikido.dev",
		},
		{
			name:        "prod us",
			apiEndpoint: "https://k8s.us.aikido-security.com",
			want:        "https://endpoint-server-ingest.us.aikido.dev",
		},
		{
			name:        "prod au",
			apiEndpoint: "https://k8s.au.aikido-security.com",
			want:        "https://endpoint-server-ingest.au.aikido.dev",
		},
		{
			name:        "prod me",
			apiEndpoint: "https://k8s.me.aikido-security.com",
			want:        "https://endpoint-server-ingest.me.aikido.dev",
		},
		{
			name:        "us gov",
			apiEndpoint: "https://k8s.aikidogov.us",
			want:        "https://endpoint-server-ingest.aikidogov.us",
		},
		{
			name:        "unrecognized host",
			apiEndpoint: "https://k8s.example.com",
			wantErr:     true,
		},
		{
			name:        "unrecognized region subdomain: no known ingest host for it",
			apiEndpoint: "https://k8s.zz.aikido-security.com",
			wantErr:     true,
		},
		{
			name:        "malformed URL",
			apiEndpoint: "://not-a-url",
			wantErr:     true,
		},
		{
			name:        "empty",
			apiEndpoint: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveRuntimeDetectionEndpoint(tt.apiEndpoint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got endpoint %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
