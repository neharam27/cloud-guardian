"""Scanner: Elastic IP addresses that are not associated with anything.

Read-only (it only calls ec2:DescribeAddresses).

Why it matters: AWS charges an hourly fee for every public IPv4 address, and an
Elastic IP that is allocated but not in use is pure waste.

Limitation worth knowing: DescribeAddresses does not report WHEN an address was
allocated, so there is no age filter here. A brand-new address that you are
about to attach will be reported until it is associated. Tag it
guardian:ignore=true if that is intentional. A precise age needs CloudTrail
(AllocateAddress events) and is a later improvement.
"""

from __future__ import annotations

from typing import Any

from .common import Finding, is_ignored, severity_for, tags_to_dict
from .pricing import estimate_public_ipv4_monthly_cost

CHECK_NAME = "eip-unassociated"


def is_associated(address: dict[str, Any]) -> bool:
    return bool(
        address.get("AssociationId")
        or address.get("InstanceId")
        or address.get("NetworkInterfaceId")
    )


def scan(ec2_client: Any, region: str) -> list[Finding]:
    """Return one Finding per unassociated, non-ignored Elastic IP."""
    findings: list[Finding] = []
    cost = estimate_public_ipv4_monthly_cost()

    # DescribeAddresses is not paginated.
    for address in ec2_client.describe_addresses()["Addresses"]:
        if is_associated(address):
            continue

        tags = tags_to_dict(address.get("Tags"))
        if is_ignored(tags):
            continue

        public_ip = address["PublicIp"]
        resource_id = address.get("AllocationId") or public_ip

        findings.append(
            Finding(
                check=CHECK_NAME,
                resource_id=resource_id,
                resource_type="AWS::EC2::EIP",
                region=region,
                estimated_monthly_cost_usd=cost,
                severity=severity_for(cost),
                recommendation=(
                    "Release the address if it is not reserved for future use. "
                    "Add the tag guardian:ignore=true to keep it."
                ),
                summary=f"Elastic IP {public_ip}, not associated with any resource",
                evidence={
                    "public_ip": public_ip,
                    "allocation_id": address.get("AllocationId"),
                    "domain": address.get("Domain"),
                    "network_border_group": address.get("NetworkBorderGroup"),
                    "tags": tags,
                    "age_known": False,
                    "cost_basis": "public IPv4 hourly charge; approximate (see pricing.py)",
                },
            )
        )

    findings.sort(key=lambda f: f.resource_id)
    return findings
