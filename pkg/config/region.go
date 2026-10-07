package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Pre-populated even for regions without ingest deployed yet, so going live there needs no
// agent release — just DNS.
var knownIngestHosts = map[string]string{
	"prod:eu":    "https://endpoint-server-ingest.aikido.dev",
	"prod:us":    "https://endpoint-server-ingest.us.aikido.dev",
	"prod:au":    "https://endpoint-server-ingest.au.aikido.dev",
	"prod:me":    "https://endpoint-server-ingest.me.aikido.dev",
	"prod:usgov": "https://endpoint-server-ingest.aikidogov.us",
	"staging:eu": "https://endpoint-server-ingest.test.aikido.dev",
}

func DeriveRuntimeDetectionEndpoint(apiEndpoint string) (string, error) {
	env, region, err := parseEnvAndRegion(apiEndpoint)
	if err != nil {
		return "", err
	}

	host, ok := knownIngestHosts[env+":"+region]
	if !ok {
		return "", fmt.Errorf("no known runtime detection ingest host for region %q (env %q)", region, env)
	}
	return host, nil
}

func parseEnvAndRegion(apiEndpoint string) (env, region string, err error) {
	u, parseErr := url.Parse(apiEndpoint)
	if parseErr != nil || u.Host == "" {
		return "", "", fmt.Errorf("could not parse apiEndpoint %q", apiEndpoint)
	}
	host := u.Host

	if host == "k8s.aikidogov.us" { // standalone domain, not a subdomain
		return "prod", "usgov", nil
	}
	if host == "k8s.staging.aikido-security.com" { // staging is eu-only today
		return "staging", "eu", nil
	}
	if host == "k8s.aikido-security.com" {
		return "prod", "eu", nil
	}
	if rest, ok := strings.CutPrefix(host, "k8s."); ok {
		if region, ok := strings.CutSuffix(rest, ".aikido-security.com"); ok {
			return "prod", region, nil
		}
	}
	return "", "", fmt.Errorf("could not determine region from apiEndpoint %q", apiEndpoint)
}
