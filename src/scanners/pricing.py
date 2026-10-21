"""Rough EBS storage cost estimates.

IMPORTANT: these are ESTIMATES used to rank findings by likely waste, not billing
data. They are built from well-known us-east-1 list prices multiplied by a rough
regional factor, and have NOT been checked against the live AWS price list.

Known gaps (all of them make the estimate too LOW, never too high):
  * provisioned IOPS / throughput charges (io1, io2, gp3 above baseline)
  * snapshot storage
  * regions missing from REGION_MULTIPLIER fall back to 1.0

A later iteration should replace this table with the AWS Pricing API.
"""

from __future__ import annotations

# USD per GB-month, us-east-1 list prices (storage only).
BASE_PRICE_PER_GIB_MONTH: dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}

# Rough multiplier versus us-east-1. Approximate; refine with the Pricing API.
REGION_MULTIPLIER: dict[str, float] = {
    "us-east-1": 1.0,
    "ap-south-1": 1.14,
    "ap-southeast-2": 1.20,
}

# Public IPv4 addresses are billed per hour, whether or not they are in use.
# Approximate list price; check the AWS pricing page before quoting it.
PUBLIC_IPV4_PRICE_PER_HOUR = 0.005
HOURS_PER_MONTH = 730

# Used when a volume type is not in the table above.
FALLBACK_PRICE_PER_GIB_MONTH = 0.10


def estimate_ebs_monthly_cost(volume_type: str, size_gib: int, region: str) -> float:
    """Return an approximate monthly storage cost in USD, rounded to cents."""
    base = BASE_PRICE_PER_GIB_MONTH.get(volume_type, FALLBACK_PRICE_PER_GIB_MONTH)
    multiplier = REGION_MULTIPLIER.get(region, 1.0)
    return round(base * multiplier * size_gib, 2)


def estimate_public_ipv4_monthly_cost() -> float:
    """Approximate monthly cost of one public IPv4 address, in USD."""
    return round(PUBLIC_IPV4_PRICE_PER_HOUR * HOURS_PER_MONTH, 2)
