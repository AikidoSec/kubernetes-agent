package models

import "slices"

type ExceptionCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ThreatDetectionException struct {
	ID         int64                `json:"id"`
	Name       string               `json:"name"`
	RuleNames  []string             `json:"rule_names"`
	Conditions []ExceptionCondition `json:"conditions"`
}

func ThreatDetectionExceptionEqual(a, b ThreatDetectionException) bool {
	return a.ID == b.ID &&
		a.Name == b.Name &&
		slices.Equal(a.RuleNames, b.RuleNames) &&
		slices.EqualFunc(a.Conditions, b.Conditions, func(ca, cb ExceptionCondition) bool {
			return ca.Field == cb.Field && ca.Operator == cb.Operator && ca.Value == cb.Value
		})
}
