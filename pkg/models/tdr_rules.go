package models

type TDRRuleAction struct {
	Disable TDRRuleSelector `yaml:"disable,omitempty"`
	Enable  TDRRuleSelector `yaml:"enable,omitempty"`
}

type TDRRuleSelector struct {
	Rule string `yaml:"rule,omitempty"`
	Tag  string `yaml:"tag,omitempty"`
}
