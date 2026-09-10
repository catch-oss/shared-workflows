#!/usr/bin/env bash
#
# Applies the ruleset definitions in .github/rulesets/ to the enterprise.
#
# repository_id is left as 0 in the committed JSON on purpose. A numeric id is
# meaningless to read and easy to leave stale, so it is resolved from the
# repository name here instead and injected at apply time.
#
# Usage:
#   scripts/apply-rulesets.sh                 # create both, in evaluate mode
#   scripts/apply-rulesets.sh <name> <id>     # update one existing ruleset
#
set -euo pipefail

ENTERPRISE="${ENTERPRISE:-catch-design-ltd}"
SOURCE_REPO="${SOURCE_REPO:-catch-oss/shared-workflows}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_ID="$(gh api "repos/${SOURCE_REPO}" -q '.id')"
if [ -z "${REPO_ID}" ] || [ "${REPO_ID}" = "null" ]; then
    echo "could not resolve a repository id for ${SOURCE_REPO}" >&2
    exit 1
fi
echo "source: ${SOURCE_REPO} (id ${REPO_ID})"

render() {
    jq --argjson id "${REPO_ID}" \
       '.rules[0].parameters.workflows[0].repository_id = $id' "$1"
}

if [ $# -eq 2 ]; then
    file="${DIR}/.github/rulesets/$1.json"
    [ -f "${file}" ] || { echo "no such ruleset definition: ${file}" >&2; exit 1; }
    render "${file}" | gh api --method PUT "/enterprises/${ENTERPRISE}/rulesets/$2" --input -
    exit 0
fi

for file in "${DIR}"/.github/rulesets/*.json; do
    echo "creating $(basename "${file}")..."
    render "${file}" | gh api --method POST "/enterprises/${ENTERPRISE}/rulesets" --input -
done
