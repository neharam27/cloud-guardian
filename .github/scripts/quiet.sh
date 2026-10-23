#!/usr/bin/env bash
# Run a command WITHOUT printing its output.
#
# This repository is public, so GitHub Actions logs are public too. Terraform's normal output
# contains account ids, ARNs, an email address and the approver URL. The full output goes to
# the file given as the first argument; the log only gets a short, sanitized excerpt, and only
# when the command fails.
#
# usage: quiet.sh LOGFILE COMMAND [ARGS...]
set -u

if [ "$#" -lt 2 ]; then
  echo "usage: quiet.sh LOGFILE COMMAND [ARGS...]" >&2
  exit 64
fi

log="$1"
shift

"$@" >"$log" 2>&1
status=$?
if [ "${status}" -eq 0 ]; then
  exit 0
fi

echo "Command failed (exit ${status}). The full output is not printed because the logs are public."
echo "Sanitized excerpt of the error lines:"
grep -E -i "error|denied|not authorized|failed|invalid|conflict|forbidden" "$log" \
  | sed -E 's/[0-9]{12}/[account-id]/g; s#https?://[^ "]+#[url]#g; s/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[email]/g' \
  | head -40
exit "$status"
