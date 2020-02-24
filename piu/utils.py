import boto3
import click
from collections import namedtuple

Instance = namedtuple("Instance", ["instance_id", "name", "stack_name", "stack_version", "private_ip"])


def _hosted_zones(route53):
    """Enumerates all Route53 hosted zones as tuples of id, name"""

    paginator = route53.get_paginator("list_hosted_zones")
    for result in paginator.paginate():
        for zone in result["HostedZones"]:
            yield zone["Id"], zone["Name"]


def find_odd_host(region):
    """Returns the Odd SSH bastion hostname for the current AWS account and the
       specified region if it exists"""
    if not region:
        return

    route53 = boto3.client("route53", region_name=region)
    for zone_id, zone_name in _hosted_zones(route53):
        candidate_host = "odd-{}.{}".format(region, zone_name)
        result = route53.list_resource_record_sets(
            HostedZoneId=zone_id, MaxItems="1", StartRecordType="A", StartRecordName=candidate_host
        )
        for record in result["ResourceRecordSets"]:
            if record["Type"] == "A" and record["Name"] == candidate_host:
                return record["Name"].rstrip(".")


def list_running_instances(region, filters):
    """Generator that yields Instance records for running EC2 instances matching the
       filter and region"""
    ec2 = boto3.resource("ec2", region_name=region)
    effective_filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    effective_filters.extend(filters)
    for instance in ec2.instances.filter(Filters=effective_filters):
        instance_id = instance.instance_id

        raw_tags = instance.tags or {}
        tags = {tag["Key"]: tag["Value"] for tag in raw_tags}

        yield Instance(
            instance_id, tags.get("Name"), tags.get("StackName"), tags.get("StackVersion"), instance.private_ip_address
        )


def current_region():
    """Returns the current AWS region"""
    session = boto3.session.Session()
    return session.region_name


def validate_region(ctx, param, value):
    """Click validator for the AWS region argument"""
    if value is not None:
        session = boto3.session.Session()
        if value not in session.get_available_regions("cloudformation"):
            raise click.BadParameter("Invalid AWS region '{}'".format(value))

    return value
