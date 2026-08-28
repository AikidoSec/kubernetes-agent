#!/usr/bin/env bash
# Update the embedded Falco rules to match a specific Falco version, preserving
# all aikido: routing tags from the current file.
#
# Note: this fetches falcosecurity/rules/rules/falco_rules.yaml (the "stable" ruleset).
# Falco also publishes falco-sandbox_rules.yaml and falco-incubating_rules.yaml in the
# same repo; we deliberately don't pull those — they're less mature and not enabled by
# default in upstream Falco. If we ever decide to route a sandbox/incubating rule, the
# script would need extending.
#
# Usage:  ./scripts/update-falco-rules.sh <falco-version>
# Example: ./scripts/update-falco-rules.sh 0.44.0
#
# Requires: curl, python3 (stdlib only), yq, jq
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

# Snapshot rule descriptions before overwriting, to detect upstream description drift.
# Only tagged (routed) rules matter here: those are the ones hand-curated in
# cloud-security's default_threat_rules.json. extract_conditions.sh (see
# FALCO_UPGRADES.md) only syncs the `condition` field on upgrade — descriptions are
# maintained separately and won't update on their own, so if upstream rewords a rule's
# `desc:`, nothing else would ever flag that the curated copy may now be stale.
OLD_DESCS=$(yq -o=json '[.[] | select(has("rule")) | {"rule": .rule, "desc": (.desc // "")}]' "$RULES_FILE")
NEW_DESCS=$(echo "$NEW_RULES" | yq -o=json '[.[] | select(has("rule")) | {"rule": .rule, "desc": (.desc // "")}]' -)

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

# Stamp the Falco version at the top of the file so the CI sync check can read it.
{ echo "# aikido-falco-version: ${VERSION}"; cat "$RULES_FILE"; } > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "$RULES_FILE"

echo "Written: $RULES_FILE"

# Report rules that had the routing tag but no longer exist in the new version.
REMOVED=$(comm -23 \
    <(echo "$OLD_TAGGED_NAMES" | grep -v '^$') \
    <(echo "$NEW_RULE_NAMES" | grep -v '^$') || true)

# Report brand-new rules that need a tagging decision.
NEW_UNTAGGED=$(comm -13 \
    <(echo "$OLD_RULE_NAMES" | grep -v '^$') \
    <(echo "$NEW_RULE_NAMES" | grep -v '^$') || true)

# Report tagged rules whose upstream `desc:` text changed in this version.
DESC_CHANGED=$(jq -r -n --argjson old "$OLD_DESCS" --argjson new "$NEW_DESCS" --arg tagged "$OLD_TAGGED_NAMES" '
    ($tagged | split("\n") | map(select(length > 0))) as $tagged_list |
    ($old | map({key: .rule, value: (.desc | rtrimstr("\n"))}) | from_entries) as $old_map |
    ($new | map({key: .rule, value: (.desc | rtrimstr("\n"))}) | from_entries) as $new_map |
    $tagged_list[] | select($old_map[.] != null and $new_map[.] != null and $old_map[.] != $new_map[.])
')

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

if [[ -n "$DESC_CHANGED" ]]; then
    echo ""
    echo "INFO: Upstream description changed for these routed rules in Falco ${VERSION}:"
    echo "$DESC_CHANGED" | sed 's/^/  ~ /'
    echo "  Review whether the curated description in cloud-security's default_threat_rules.json still holds."
fi

echo ""
echo -e "\033[1mAlways review the diff before committing — tag injection relies on the rules file\nkeeping its current YAML structure and may silently miss rules if the format changes.\033[0m"
