#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

gh api repos/GoCodeAlone/mission-control-edge/branches/main/protection --method PUT --input .github/branch-protection.json

verified=$(gh api repos/GoCodeAlone/mission-control-edge/branches/main/protection --jq '
  ((.required_status_checks.contexts | sort) == [
    "ci/conformance",
    "ci/go",
    "ci/release-snapshot",
    "ci/security",
    "ci/typescript"
  ]) and
  (.required_status_checks.strict == true) and
  (.enforce_admins.enabled == false) and
  (.required_pull_request_reviews.dismiss_stale_reviews == true) and
  (.required_pull_request_reviews.require_code_owner_reviews == true) and
  (.required_pull_request_reviews.require_last_push_approval == true) and
  (.required_pull_request_reviews.required_approving_review_count == 1) and
  (.restrictions == null) and
  (.required_linear_history.enabled == true) and
  (.allow_force_pushes.enabled == false) and
  (.allow_deletions.enabled == false) and
  (.required_conversation_resolution.enabled == true)
')

if test "$verified" != true; then
  echo "branch protection read-back did not match .github/branch-protection.json" >&2
  exit 1
fi

echo "mission-control-edge main branch protection verified"
