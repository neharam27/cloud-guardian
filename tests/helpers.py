"""Small shared helpers for tests that need a fake SNS topic and a way to read its emails."""

import json

import boto3

REGION = "ap-south-1"


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
