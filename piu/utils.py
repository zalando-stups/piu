import boto3
import click


def _hosted_zones(route53):
    """Enumerates all Route53 hosted zones as tuples of id, name"""

    paginator = route53.get_paginator('list_hosted_zones')
    for result in paginator.paginate():
        for zone in result['HostedZones']:
            yield zone['Id'], zone['Name']


def find_odd_host(region):
    """Returns the Odd SSH bastion hostname for the current AWS account and the
       specified region if it exists"""
    if not region:
        return

    route53 = boto3.client('route53', region_name=region)
    for zone_id, zone_name in _hosted_zones(route53):
        candidate_host = "odd-{}.{}".format(region, zone_name)
        result = route53.list_resource_record_sets(
            HostedZoneId=zone_id, MaxItems='1',
            StartRecordType='A', StartRecordName=candidate_host)
        for record in result['ResourceRecordSets']:
            if record['Type'] == 'A' and record['Name'] == candidate_host:
                return record['Name'].rstrip('.')


def current_region():
    """Returns the current AWS region"""
    session = boto3.session.Session()
    return session.region_name


def validate_region(ctx, param, value):
    """Click validator for the AWS region argument"""
    if value is not None:
        session = boto3.session.Session()
        if value not in session.get_available_regions('cloudformation'):
            raise click.BadParameter("Invalid AWS region '{}'".format(value))

    return value
