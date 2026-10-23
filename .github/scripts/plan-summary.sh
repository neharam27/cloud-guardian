#!/usr/bin/env bash
# Summarize a Terraform plan (JSON) for a PUBLIC log: resource addresses and actions only,
# never attribute values.
#
# usage: plan-summary.sh PLAN.json
#
# Prints the list, and when running in GitHub Actions also writes:
#   $GITHUB_OUTPUT        changes=<n> and destroys=<n>
#   $GITHUB_STEP_SUMMARY  a short report
#
# "destroys" counts every resource that is deleted, including ones that are replaced.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: plan-summary.sh PLAN.json" >&2
  exit 64
fi

plan_json="$1"

changed=$(jq -c '[.resource_changes[]? | select(.mode == "managed") | select(.change.actions != ["no-op"])]' "$plan_json")
total=$(jq 'length' <<<"$changed")
destroys=$(jq '[.[] | select(.change.actions | index("delete"))] | length' <<<"$changed")
lines=$(jq -r '.[] | "- " + (.change.actions | join(" then ")) + ": `" + .address + "`"' <<<"$changed")

report() {
  echo "### Terraform plan"
  echo
  if [ "$total" -eq 0 ]; then
    echo "No changes. The deployed infrastructure matches the code."
  else
    echo "${total} resource(s) would change, ${destroys} would be destroyed:"
    echo
    echo "$lines"
    if [ "$destroys" -gt 0 ]; then
      echo
      echo "**Warning: this plan destroys resources.** The apply job refuses to run it unless you start the workflow by hand with \`allow_destroy\` ticked."
    fi
  fi
}

report

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "changes=${total}"
    echo "destroys=${destroys}"
  } >>"$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  report >>"$GITHUB_STEP_SUMMARY"
fi
