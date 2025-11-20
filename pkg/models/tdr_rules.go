package models

type ThreatDetectionRuleAction struct {
	Disable ThreatDetectionRuleSelector `yaml:"disable,omitempty"`
	Enable  ThreatDetectionRuleSelector `yaml:"enable,omitempty"`
}

type ThreatDetectionRuleSelector struct {
	Rule string `yaml:"rule,omitempty"`
	Tag  string `yaml:"tag,omitempty"`
}
