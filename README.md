# Cloud Guardian

A serverless AWS cost-governance tool. Every day it scans an account for forgotten, wasteful resources, estimates what each one costs per month, and emails a ranked report.

**Status: early build.** Three read-only scanners (unattached EBS volumes, unassociated Elastic IPs, old snapshots). Nothing is ever modified or deleted.

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

## Cost estimates: read this

Estimates are approximate list prices (`src/scanners/pricing.py`) and are **not** checked against the live AWS price list.

- EBS: storage only, from us-east-1 prices times a rough regional multiplier. Provisioned IOPS, throughput and snapshot costs are ignored, so this under-estimates.
- Elastic IP: the public IPv4 hourly charge times 730 hours.
- Snapshots: full source-volume size at the standard-tier price, with no regional adjustment. Snapshots are incremental, so real cost is usually lower.

Treat them as a ranking signal, not billing data.

## Known limitations

- `MIN_AGE_DAYS` filters on volume *creation* age, because `DescribeVolumes` does not report when a volume was detached. A precise "unattached for N days" needs CloudTrail.
- `DescribeAddresses` reports no allocation time, so Elastic IPs have no age filter: a brand-new address you are about to attach is reported until it is associated. Tag it `guardian:ignore=true` if that matters.

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
- [ ] More scanners: long-stopped EC2, idle RDS, untagged resources
- [x] Findings history in DynamoDB, change-only emails, weekly digest
- [ ] Simple dashboard
- [ ] Approval-gated remediation (Step Functions): expiring approvals, idempotency, revalidation before acting, dry-run by default
- [ ] Safety test suite: refuses on `guardian:ignore`, expired approval, changed state, duplicate action, out-of-scope resource
- [ ] GitHub Actions deploy via OIDC (no stored keys)
- [ ] Reproducible evaluation on seeded waste scenarios (precision, recall, scan time)
- [ ] Optional: AI-written explanations of findings (never makes decisions)

## Repo layout

```
src/handler.py                     Lambda entry point, scanner orchestration, report formatting
src/findings_store.py              Findings history (DynamoDB): new / still open / resolved
src/scanners/common.py             Finding type and shared helpers (ignore tag, severity)
src/scanners/ebs_unattached.py     Unattached EBS volumes
src/scanners/eip_unassociated.py   Unassociated Elastic IPs
src/scanners/snapshots_old.py      Old, unused snapshots
src/scanners/pricing.py            Cost estimation (approximate)
tests/                             pytest + moto (mocked AWS, no account needed)
terraform/                         Main stack
terraform/bootstrap/               One-time state bucket
.github/workflows/ci.yml           Lint, test, terraform validate, Checkov, gitleaks
```
