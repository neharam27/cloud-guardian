# Cloud Guardian

A serverless AWS cost-governance tool. Every day it scans an account for forgotten, wasteful resources, estimates what each one costs per month, and emails a ranked report.

**Status: early build.** Four read-only scanners (unattached EBS volumes, unassociated Elastic IPs, old snapshots, long-stopped EC2 instances). Nothing is ever modified or deleted.

## How it works

```
EventBridge Scheduler (daily)
        |
        v
Lambda: scanner --ec2:Describe* (read-only)--> EC2
        |  \
        |   +--> DynamoDB: findings history (open / resolved, first and last seen)
        v
SNS topic (encrypted) --> email: only what changed, plus a weekly digest
```

## What it checks

| Check | What it finds | API used |
|---|---|---|
| `ebs-unattached-volume` | EBS volumes attached to nothing | `ec2:DescribeVolumes` |
| `eip-unassociated` | Elastic IPs allocated but not in use | `ec2:DescribeAddresses` |
| `ebs-old-snapshot` | Your own snapshots older than `snapshot_min_age_days` (default 90) that no AMI uses and no lifecycle service manages | `ec2:DescribeSnapshots`, `DescribeImages`, `DescribeVolumes` |
| `ec2-long-stopped-instance` | Instances stopped for at least `stopped_min_age_days` (default 14). Compute is free while stopped, but the attached disks keep billing | `ec2:DescribeInstances`, `DescribeVolumes` |

## Change-only reporting

Emailing the same list every morning trains people to ignore the email. Findings are stored in DynamoDB, and the daily email covers only what changed:

- **New** findings since the last report
- **Resolved** findings (they stopped appearing)
- a one-line count of everything still open

Once a week (Monday UTC by default, `digest_weekday`) the email lists every open finding. Invoke the Lambda with `{"digest": true}` to get a digest on demand.

Two rules keep the history trustworthy:

- **A finding is only marked announced after the email was actually sent.** If publishing fails, the next run announces it again, so nothing is lost silently.
- **A scanner that crashed never resolves anything.** "I could not look" is not "it is gone", so that scanner's open findings stay open until it succeeds again.

If the history table itself fails, the scan falls back to emailing every finding and says so in the report. A broken history must never hide waste.

## Design

- **Least privilege:** the scanner's role can call those read-only EC2 APIs, publish to one SNS topic, read and write one DynamoDB table (no delete, no scan), and write its own logs. Nothing else.
- **Opt-out:** tag any resource `guardian:ignore=true` and it is never reported.
- **Evidence on every finding:** the facts a human needs to judge it, plus the cost basis.
- **Failure isolation:** if one scanner errors, the others still run and the email says which one failed (without leaking the error text).
- **Infrastructure as code:** everything is Terraform; state lives in S3 with native locking (no DynamoDB table).

## Approval-gated clean-up (core built, not deployed yet)

Scanning is read-only. Acting is a separate, much stricter path, and the first action is deleting one unattached EBS volume. The code is in `src/remediation/` and is covered by tests; it is **not yet connected to the emails or deployed**, so today nothing in AWS can trigger it.

The rules, each one backed by a test that fails if the rule is removed:

- **A human approves every action.** An approval is a random one-time token. Only its SHA-256 hash is stored, so the table never holds a usable link. It expires after 24 hours and can be used exactly once, even if two people click at the same moment.
- **Dry run is the default** and changes nothing. A dry run does not use the approval up.
- **The target is checked at the moment of action,** with the very same function the scanner uses (`evaluate_volume`). Attached since the report? Tagged `guardian:ignore` since? Too new? Then it refuses. Already gone? Nothing to do, and that is not an error.
- **Back up first.** A snapshot is taken and must be `completed`, and must be a snapshot of this exact volume, before the volume is touched. If the backup fails or stalls, nothing is deleted.
- **Strict scope.** Only a well-formed `vol-…` id in this region, from the `ebs-unattached-volume` check. Anything else is refused.
- **Only one delete call, with the validated id.** If AWS errors midway, the result says so without leaking error text, and the approval stays used so a human has to ask again. "Never twice" matters more than "retry for me".
- **Everything is recorded** against the approval (outcome and detail) as an audit trail.

Still to build: approval links in the email (the link opens a confirmation page and only a button press acts, because email scanners pre-fetch links), a separate write-capable role limited to this one action with an IAM deny on `guardian:ignore` as a second safety layer, and a Step Functions workflow that runs the steps with waits and retries.

## Cost estimates: read this

Estimates are approximate list prices (`src/scanners/pricing.py`) and are **not** checked against the live AWS price list.

- EBS: storage only, from us-east-1 prices times a rough regional multiplier. Provisioned IOPS, throughput and snapshot costs are ignored, so this under-estimates.
- Elastic IP: the public IPv4 hourly charge times 730 hours.
- Snapshots: full source-volume size at the standard-tier price, with no regional adjustment. Snapshots are incremental, so real cost is usually lower.
- Stopped instances: the attached EBS volumes only, priced like the EBS estimate above. Snapshots, AMIs and Elastic IPs tied to the instance are not counted.

Treat them as a ranking signal, not billing data.

## Known limitations

- `MIN_AGE_DAYS` filters on volume *creation* age, because `DescribeVolumes` does not report when a volume was detached. A precise "unattached for N days" needs CloudTrail.
- `DescribeAddresses` reports no allocation time, so Elastic IPs have no age filter: a brand-new address you are about to attach is reported until it is associated. Tag it `guardian:ignore=true` if that matters.

- "Stopped for N days" comes from the timestamp inside the instance's `StateTransitionReason` text (`DescribeInstances` has no stop-time field). Some stops carry no timestamp, for example a shutdown from inside the operating system. For those the stop time is unknown: an instance launched less than `stopped_min_age_days` ago is skipped, and an older one is reported but marked "stop time unknown" instead of guessing. CloudTrail would give an exact answer and is a later improvement.
- Snapshots are skipped when an AMI you own references them, or when they carry a `dlm:managed` or `aws:backup*` tag. Deleting one snapshot in a chain may free little space, because later snapshots can depend on its blocks.

## Quick start

Prerequisites: AWS CLI v2 with credentials configured (`aws configure` with an IAM user; do not enable IAM Identity Center or AWS Organizations on a Free plan account, since AWS says that converts it to a paid plan), Terraform >= 1.10, Python 3.12+.

Some accounts (for example ones managed under an organization) only allow certain regions. Check that EC2, Lambda, SNS, Scheduler and S3 respond in your region before deploying, and set `region` in `terraform.tfvars` and `backend.hcl` to match.

macOS / Linux:

```bash
# 0. Local checks
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q

# 1. One-time: create the Terraform state bucket
cd terraform/bootstrap
terraform init && terraform apply -var="region=YOUR_REGION"
# note the "state_bucket" output

# 2. Deploy the stack
cd ..
cp backend.hcl.example backend.hcl            # put your bucket and region in
cp terraform.tfvars.example terraform.tfvars  # put your email and region in
terraform init -backend-config=backend.hcl
terraform plan
terraform apply

# 3. Confirm the subscription email from AWS, then run a scan now
aws lambda invoke --function-name cloud-guardian-scanner --region YOUR_REGION \
  --cli-binary-format raw-in-base64-out --payload '{}' out.json && cat out.json
```

Windows (PowerShell) differs in three places:

```powershell
.venv\Scripts\Activate.ps1                                  # instead of source
copy backend.hcl.example backend.hcl                        # instead of cp
terraform init "-backend-config=backend.hcl"                # quotes are required
aws lambda invoke --function-name cloud-guardian-scanner --region YOUR_REGION --cli-binary-format raw-in-base64-out --payload "{}" out.json
type out.json
```

To see real findings, create a tiny test volume and an Elastic IP (both cost a few cents), set `min_age_days = 0` in `terraform.tfvars`, apply, and run the scan:

```bash
aws ec2 create-volume --availability-zone YOUR_REGIONa --size 1 --volume-type gp3 --region YOUR_REGION
aws ec2 allocate-address --domain vpc --region YOUR_REGION
```

Delete both afterwards (`aws ec2 delete-volume ...`, `aws ec2 release-address --allocation-id ...`). To remove the whole stack: `terraform destroy` in `terraform/`.

## Looking at the history

```bash
aws dynamodb scan --table-name cloud-guardian-findings --region YOUR_REGION \
  --query "Items[].[status.S,check.S,resource_id.S,first_seen.S,last_seen.S]" --output table
```

The table is not backed up on purpose: it is derived from AWS state, so losing it only restarts the first-seen history. (Your own IAM user can scan it; the Lambda's role cannot.)

## Staying inside free credits

All services used here (Lambda, SNS, EventBridge Scheduler, S3, DynamoDB on-demand, CloudWatch Logs) are effectively free at this scale. Avoid NAT gateways, load balancers and RDS instances in anything you add. Set a Budget alert before deploying.

## Roadmap

- [x] Unattached EBS scanner, Terraform, tests, CI
- [x] Unassociated Elastic IP scanner, multi-scanner handler with failure isolation
- [x] Old-snapshot scanner with AMI-in-use and lifecycle-managed exclusions
- [x] Long-stopped EC2 instances scanner
- [ ] More scanners: idle RDS, untagged resources
- [x] Findings history in DynamoDB, change-only emails, weekly digest
- [ ] Simple dashboard
- [x] Approval-gated clean-up core for unattached EBS volumes: one-time expiring approvals, re-check before acting, backup before delete, dry-run by default
- [x] Safety test suite for that core: refuses on `guardian:ignore`, expired or used approval, changed state, duplicate action, out-of-scope resource (each guard verified by breaking it on purpose)
- [ ] Connect it: approval links in the email, narrowly scoped write role, Step Functions workflow
- [ ] Try it end to end on a real test volume
- [ ] GitHub Actions deploy via OIDC (no stored keys)
- [ ] Reproducible evaluation on seeded waste scenarios (precision, recall, scan time)
- [ ] Optional: AI-written explanations of findings (never makes decisions)

## Repo layout

```
src/handler.py                     Lambda entry point, scanner orchestration, report formatting
src/findings_store.py              Findings history (DynamoDB): new / still open / resolved
src/remediation/approvals.py       One-time, expiring approval tokens (DynamoDB, hashed)
src/remediation/ebs_delete.py      Back up then delete one unattached volume, with guards
src/remediation/executor.py        Approval to action, plus an audit record
src/scanners/common.py             Finding type and shared helpers (ignore tag, severity)
src/scanners/ebs_unattached.py     Unattached EBS volumes
src/scanners/eip_unassociated.py   Unassociated Elastic IPs
src/scanners/snapshots_old.py      Old, unused snapshots
src/scanners/ec2_stopped.py        Long-stopped EC2 instances and the disks they still bill for
src/scanners/pricing.py            Cost estimation (approximate)
tests/                             pytest + moto (mocked AWS, no account needed)
terraform/                         Main stack
terraform/bootstrap/               One-time state bucket
.github/workflows/ci.yml           Lint, test, terraform validate, Checkov, gitleaks
```
