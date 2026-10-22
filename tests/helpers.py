"""Small shared helpers for tests that need a fake SNS topic and a way to read its emails."""

import json

import boto3
from botocore.exceptions import ClientError

from scanners import ebs_unattached

REGION = "ap-south-1"
AZ = "ap-south-1a"


def make_topic_with_queue():
    """Create an SNS topic whose messages land in an SQS queue we can read back."""
    sns = boto3.client("sns", region_name=REGION)
    sqs = boto3.client("sqs", region_name=REGION)
    topic_arn = sns.create_topic(Name="guardian-test")["TopicArn"]
    queue_url = sqs.create_queue(QueueName="guardian-test-q")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    return topic_arn, sqs, queue_url


def read_emails(sqs, queue_url):
    """Return every email delivered since the last call, as {'Subject':..., 'Message':...}."""
    messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
    return [json.loads(m["Body"]) for m in messages]


def read_email(sqs, queue_url):
    emails = read_emails(sqs, queue_url)
    assert emails, "expected an email but none arrived"
    return emails[0]


# --- EBS volumes and Cloud Guardian backups (shared by the clean-up tests) ---------


def make_volume(ec2, size=10, tags=None):
    kwargs = {"AvailabilityZone": AZ, "Size": size, "VolumeType": "gp3"}
    if tags:
        kwargs["TagSpecifications"] = [
            {
                "ResourceType": "volume",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    return ec2.create_volume(**kwargs)["VolumeId"]


def finding_id(volume_id, region=REGION, check=ebs_unattached.CHECK_NAME):
    return f"{check}#{region}#{volume_id}"


def volume_exists(ec2, volume_id):
    try:
        ec2.describe_volumes(VolumeIds=[volume_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return False
        raise
    return True


def backups(ec2):
    """Snapshots created by Cloud Guardian (identified by our tag)."""
    found = []
    for snap in ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]:
        tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
        if "guardian:backup-of" in tags:
            found.append((snap, tags))
    return found
