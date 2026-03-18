#!/usr/bin/env bash
# Update the embedded Falco rules to match a specific Falco version, preserving
# all aikido: routing tags from the current file.
#
# Usage:  ./scripts/update-falco-rules.sh <falco-version>
# Example: ./scripts/update-falco-rules.sh 0.44.0
#
# Requires: curl, python3 (stdlib only)
set -euo pipefail

AIKIDO_TAG="aikido:threat-detection"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <falco-version>" >&2
    echo "Example: $0 0.44.0" >&2
    exit 1
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$SCRIPT_DIR/../internal/falco/rules/aikido_threat_rules.yaml"

# Resolve the falcosecurity/rules submodule commit pinned in this Falco release.
echo "Looking up rules submodule commit for Falco ${VERSION}..."
COMMIT=$(curl -sf \
    "https://api.github.com/repos/falcosecurity/falco/contents/submodules/falcosecurity-rules?ref=${VERSION}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['sha'])")
echo "  submodule commit: ${COMMIT}"

echo "Downloading falco_rules.yaml..."
NEW_RULES=$(curl -sf \
    "https://raw.githubusercontent.com/falcosecurity/rules/${COMMIT}/rules/falco_rules.yaml")

# Snapshot rule names from the current file before overwriting.
OLD_RULE_NAMES=$(awk '/^- rule:/ { print substr($0, index($0, ": ") + 2) }' "$RULES_FILE" | sort)
OLD_TAGGED_NAMES=$(awk '
    /^- rule:/ { rule = substr($0, index($0, ": ") + 2) }
    /tags:.*aikido:threat-detection/ { print rule }
' "$RULES_FILE" | sort)

NEW_RULE_NAMES=$(echo "$NEW_RULES" | awk '/^- rule:/ { print substr($0, index($0, ": ") + 2) }' | sort)

# Write tagged rule names to a temp file for awk lookup.
TAGGED_FILE=$(mktemp)
trap 'rm -f "$TAGGED_FILE"' EXIT
echo "$OLD_TAGGED_NAMES" > "$TAGGED_FILE"

# Rewrite the rules file: inject aikido:threat-detection into rules that had it
# before, preserving all comments and original formatting.
echo "$NEW_RULES" | awk \
    -v tagged_file="$TAGGED_FILE" \
    -v aikido_tag="$AIKIDO_TAG" '
BEGIN {
    while ((getline line < tagged_file) > 0) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") tagged[line] = 1
    }
}
/^- rule:/ {
    current_rule = substr($0, index($0, ": ") + 2)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", current_rule)
}
/^[[:space:]]+tags:/ && (current_rule in tagged) && ($0 !~ aikido_tag) {
    sub(/\][[:space:]]*$/, ", " aikido_tag "]")
}
{ print }
' > "$RULES_FILE"

echo "Written: $RULES_FILE"

# Report rules that had the routing tag but no longer exist in the new version.
REMOVED=$(comm -23 \
    <(echo "$OLD_TAGGED_NAMES" | grep -v '^$') \
    <(echo "$NEW_RULE_NAMES" | grep -v '^$') || true)

# Report brand-new rules that need a tagging decision.
NEW_UNTAGGED=$(comm -13 \
    <(echo "$OLD_RULE_NAMES" | grep -v '^$') \
    <(echo "$NEW_RULE_NAMES" | grep -v '^$') || true)

if [[ -n "$REMOVED" ]]; then
    echo ""
    echo "WARNING: These previously-tagged rules no longer exist in Falco ${VERSION}:"
    echo "$REMOVED" | sed 's/^/  - /'
    echo "  Remove them from the enabled rules list in cloud-security if present."
fi

if [[ -n "$NEW_UNTAGGED" ]]; then
    echo ""
    echo "INFO: New rules in Falco ${VERSION} (no ${AIKIDO_TAG} tag added):"
    echo "$NEW_UNTAGGED" | sed 's/^/  + /'
    echo "  Review and add '${AIKIDO_TAG}' to any that should route to threat detection."
fi

echo ""
echo -e "\033[1mAlways review the diff before committing — tag injection relies on the rules file\nkeeping its current YAML structure and may silently miss rules if the format changes.\033[0m"
