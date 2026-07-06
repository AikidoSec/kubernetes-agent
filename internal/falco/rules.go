package falco

import _ "embed"

//go:embed rules/aikido_threat_rules.yaml
var EmbeddedThreatRules []byte
