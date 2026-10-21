# Cloud Guardian

A serverless AWS cost-governance tool. Every day it scans an account for forgotten, wasteful resources, estimates what each one costs per month, and emails a ranked report.

**Status: week 1 (first slice).** One scanner (unattached EBS volumes), fully read-only. Nothing is ever modified or deleted.

## How it works

```
EventBridge Scheduler (daily)
        |
        v
Lambda: ebs-scanner  --ec2:DescribeVolumes-->  EC2
        |
        v
SNS topic (encrypted) --> email report
```

- **Least privilege:** the scanner's role can call `ec2:DescribeVolumes`, publish to one SNS topic, and write its own logs. Nothing else.
- **Opt-out:** tag any resource `guardian:ignore=true` and it is never reported.
- **Evidence on every finding:** size, type, age, tags and the cost basis, so a human can judge it.
- **Infrastructure as code:** everything is Terraform; state lives in S3 with native locking (no DynamoDB table).

## Cost estimates: read this

Estimates are storage-only list prices derived from us-east-1 prices and a rough regional multiplier (`src/scanners/pricing.py`). They have **not** been checked against the live AWS price list and they ignore provisioned IOPS, throughput and snapshot costs, so they under-estimate. Treat them as a ranking signal, not billing data.

`MIN_AGE_DAYS` filters on volume *creation* age, because `DescribeVolumes` does not report when a volume was detached. A precise "unattached for N days" needs CloudTrail.

## Quick start

Prerequisites: AWS CLI v2 with credentials configured (`aws configure` with an IAM user; do not enable IAM Identity Center or AWS Organizations on a Free plan account, since AWS says that converts it to a paid plan), Terraform >= 1.10, Python 3.12+.

```bash
# 0. Local checks
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q

# 1. One-time: create the Terraform state bucket
cd terraform/bootstrap
terraform init && terraform apply
# note the "state_bucket" output

# 2. Deploy the stack
cd ..
cp backend.hcl.example backend.hcl            # put your bucket name in
cp terraform.tfvars.example terraform.tfvars  # put your email in
terraform init -backend-config=backend.hcl
terraform plan
terraform apply

# 3. Confirm the subscription email from AWS, then run a scan now
terraform output -raw invoke_command | bash
```

To see a real finding, create a tiny test volume (it costs a few cents a month), then run the scan with `MIN_AGE_DAYS=0`:

```bash
aws ec2 create-volume --availability-zone ap-south-1a --size 1 --volume-type gp3 \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=project,Value=cloud-guardian-demo}]'
```

Delete it afterwards. To remove the whole stack: `terraform destroy` in `terraform/`.

## Staying inside free credits

All services used here (Lambda, SNS, EventBridge Scheduler, S3, CloudWatch Logs) are effectively free at this scale. Avoid NAT gateways, load balancers and RDS instances in anything you add. Set a Budget alert before deploying.

## Roadmap

- [x] Week 1: unattached EBS scanner, Terraform, tests, CI
- [ ] More scanners: unassociated Elastic IPs, old snapshots, long-stopped EC2, idle RDS, untagged resources
- [ ] Findings history in DynamoDB, daily digest, simple dashboard
- [ ] Approval-gated remediation (Step Functions): expiring approvals, idempotency, revalidation before acting, dry-run by default
- [ ] Safety test suite: refuses on `guardian:ignore`, expired approval, changed state, duplicate action, out-of-scope resource
- [ ] GitHub Actions deploy via OIDC (no stored keys)
- [ ] Reproducible evaluation on seeded waste scenarios (precision, recall, scan time)
- [ ] Optional: AI-written explanations of findings (never makes decisions)

## Repo layout

```
src/handler.py            Lambda entry point and report formatting
src/scanners/             One module per check
src/scanners/pricing.py   Cost estimation (approximate)
tests/                    pytest + moto (mocked AWS, no account needed)
terraform/                Main stack
terraform/bootstrap/      One-time state bucket
.github/workflows/ci.yml  Lint, test, terraform validate, Checkov, gitleaks
```
