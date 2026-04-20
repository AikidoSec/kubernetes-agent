#!/usr/bin/env bash
# Extract condition strings from the Falco rules YAML and inject them
# into cloud-security's default_threat_rules.json.
#
# Usage:
#   ./scripts/extract_conditions.sh \
#     internal/falco/rules/aikido_threat_rules.yaml \
#     /path/to/cloud-security/services/knowledge/default_threat_rules.json
#
# Requires: yq (https://github.com/mikefarah/yq), jq
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <falco-rules-yaml> <default-threat-rules-json>" >&2
    exit 1
fi

YAML_FILE="$1"
JSON_FILE="$2"

# Extract all rules from the YAML as a JSON array [{rule, condition}, ...].
# yq handles folded (>) and literal (|) block scalars transparently.
conditions=$(yq -o=json '[.[] | select(has("rule")) | {"rule": .rule, "condition": .condition}]' "$YAML_FILE")

# Build a slug→condition map and inject into the rules JSON.
# Slug matches the key format in default_threat_rules.json:
#   lowercase, runs of non-alphanumeric characters replaced with a single underscore.
result=$(jq --argjson conditions "$conditions" '
    ($conditions | map({
        key: (.rule | ascii_downcase | gsub("[^a-z0-9]+"; "_")),
        value: (.condition | gsub("[\\s]+"; " ") | ltrimstr(" ") | rtrimstr(" "))
    }) | from_entries) as $cmap |
    to_entries | map(
        if $cmap[.key] then .value.condition = $cmap[.key] else . end
    ) | from_entries
' "$JSON_FILE")

echo "$result" > "$JSON_FILE"

total=$(echo "$conditions" | jq 'length')
matched=$(echo "$result" | jq '[to_entries[] | select(.value | has("condition"))] | length')
echo "Updated $matched/$total rules with conditions."

missing=$(echo "$result" | jq -r 'to_entries[] | select(.value | has("condition") | not) | "  \(.key) (\(.value.rule_name))"')
if [[ -n "$missing" ]]; then
    echo "JSON rules with no condition extracted (slug mismatch?):"
    echo "$missing"
fi
