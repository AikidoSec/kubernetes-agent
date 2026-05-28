package models

type FalcoRuleAction struct {
	Disable FalcoRuleSelector `yaml:"disable,omitempty"`
	Enable  FalcoRuleSelector `yaml:"enable,omitempty"`
}

type FalcoRuleSelector struct {
	Rule string `yaml:"rule,omitempty"`
	Tag  string `yaml:"tag,omitempty"`
}
