"""Shared fixtures. All AWS calls in tests hit moto's in-memory fake, never a real account."""

import boto3
import pytest
from moto import mock_aws

REGION = "ap-south-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
    monkeypatch.delenv("MIN_AGE_DAYS", raising=False)


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


@pytest.fixture
def approvals_table(ec2):
    """A fake approvals table with the schema Terraform will create for it."""
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName="guardian-approvals",
        KeySchema=[{"AttributeName": "approval_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "approval_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def findings_table(ec2):
    """A fake findings table with the same schema Terraform creates.

    Depends on `ec2` only so that it runs inside the same moto mock.
    """
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName="guardian-findings",
        KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "finding_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "by-status",
                "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
