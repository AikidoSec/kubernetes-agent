package falco

import _ "embed"

//go:embed rules/aikido_threat_rules.yaml
var EmbeddedThreatRules []byte

//go:embed rules/aikido_runtime_sca_rules.yaml
var EmbeddedRuntimeSCARules []byte
