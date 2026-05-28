package models

type ThreatRuleAction struct {
	Disable ThreatRuleSelector `yaml:"disable,omitempty"`
	Enable  ThreatRuleSelector `yaml:"enable,omitempty"`
}

type ThreatRuleSelector struct {
	Rule string `yaml:"rule,omitempty"`
	Tag  string `yaml:"tag,omitempty"`
}
