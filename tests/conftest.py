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
