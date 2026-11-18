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

// KeyRule describes how a single label or annotation key is rewritten.
type KeyRule struct {
	Rename   *string           `yaml:"rename"`
	ValueMap map[string]string `yaml:"valueMap"`
	Drop     bool              `yaml:"drop"`
}

// IsEmpty reports whether no rules are configured.
func (m MetadataTransforms) IsEmpty() bool {
	return len(m.Labels) == 0 && len(m.Annotations) == 0
}

// Validate returns all invalid rules.
func (m MetadataTransforms) Validate() error {
	var errs error
	errs = multierr.Append(errs, validateRules("labels", m.Labels))
	errs = multierr.Append(errs, validateRules("annotations", m.Annotations))
	return errs
}

func validateRules(section string, rules map[string]KeyRule) error {
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
		if rule.Drop && (rule.Rename != nil || len(rule.ValueMap) > 0) {
			errs = multierr.Append(errs, fmt.Errorf("%s[%q]: drop cannot be combined with rename or valueMap", section, key))
		}
		if rule.Rename != nil && *rule.Rename == "" {
			errs = multierr.Append(errs, fmt.Errorf("%s[%q]: rename target must not be empty", section, key))
		}
	}
	return errs
}
