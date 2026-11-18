package models

import (
	"fmt"
	"sort"

	"go.uber.org/multierr"
)

// MetadataTransforms holds per-key rules applied to labels and annotations before upload.
type MetadataTransforms struct {
	Labels      map[string]KeyRule `yaml:"labels"`
	Annotations map[string]KeyRule `yaml:"annotations"`
}

// protectedLabelKeys and protectedAnnotationKeys are read by name or value downstream and cannot be rewritten.
var (
	protectedLabelKeys      = map[string]struct{}{"kubernetes.io/service-name": {}}
	protectedAnnotationKeys = map[string]struct{}{
		"kubernetes.io/ingress.class":                 {},
		"ingressclass.kubernetes.io/is-default-class": {},
		"getambassador.io/config":                     {},
		"cloud.google.com/neg-status":                 {},
	}
)

// KeyRule describes how a single label or annotation key is rewritten.
type KeyRule struct {
	Rename   *string           `yaml:"rename"`
	ValueMap map[string]string `yaml:"valueMap"`
	Redact   bool              `yaml:"redact"`
}

// IsEmpty reports whether no rules are configured.
func (m MetadataTransforms) IsEmpty() bool {
	return len(m.Labels) == 0 && len(m.Annotations) == 0
}

// Validate returns all invalid rules.
func (m MetadataTransforms) Validate() error {
	var errs error
	errs = multierr.Append(errs, validateRules("labels", m.Labels, protectedLabelKeys))
	errs = multierr.Append(errs, validateRules("annotations", m.Annotations, protectedAnnotationKeys))
	return errs
}

func validateRules(section string, rules map[string]KeyRule, protected map[string]struct{}) error {
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var errs error
	for _, key := range keys {
		rule := rules[key]
		if key == "" {
			errs = multierr.Append(errs, fmt.Errorf("%s: empty key", section))
		}
		if _, ok := protected[key]; ok {
			errs = multierr.Append(errs, fmt.Errorf("%s[%q]: key cannot be transformed", section, key))
		}
		if rule.Redact && len(rule.ValueMap) > 0 {
			errs = multierr.Append(errs, fmt.Errorf("%s[%q]: redact cannot be combined with valueMap", section, key))
		}
		if rule.Rename != nil && *rule.Rename == "" {
			errs = multierr.Append(errs, fmt.Errorf("%s[%q]: rename target must not be empty", section, key))
		}
		if rule.Rename != nil {
			if _, ok := protected[*rule.Rename]; ok {
				errs = multierr.Append(errs, fmt.Errorf("%s[%q]: rename target %q cannot be used", section, key, *rule.Rename))
			}
		}
	}
	return errs
}
