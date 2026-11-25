"""Bounded allowlisted policy diagnostics. Never publish source messages/values."""
import re
from collections import Counter

# IDs are existing Rego category identifiers. Reasons identify fixed deny templates,
# not new security controls or severities. Captured resource values are discarded.
TEMPLATES = [
 ('INPUT','INVALID_PLAN_ENVELOPE',r'INPUT: expected Terraform plan JSON with planned_values\.root_module'),
 ('IAM','INVALID_POLICY',r'IAM: .+ has unknown or invalid policy JSON'),
 ('IAM','WILDCARD_ACTION',r'IAM: .+ allows wildcard actions'),
 ('IAM','ALLOW_NOT_ACTION',r'IAM: .+ uses Allow with NotAction'),
 ('SSH','PUBLIC_SSH',r'SSH: .+ exposes SSH to the world'),
 ('S3_PUBLIC','PUBLIC_ACCESS_BLOCKS_NOT_ESTABLISHED',r'S3_PUBLIC: .+ requires all four public access blocks'),
 ('S3_PUBLIC','PUBLIC_ACL',r'S3_PUBLIC: .+ enables a public ACL'),
 ('S3_ENCRYPTION','ENCRYPTION_NOT_ESTABLISHED',r'S3_ENCRYPTION: .+ requires explicit known encryption'),
 ('TAGS','REQUIRED_TAG_MISSING',r'TAGS: .+ missing (?:Project|Environment|ManagedBy)'),
 ('TAGS','MANAGED_BY_INVALID',r'TAGS: .+ ManagedBy must be Terraform'),
 ('UNKNOWN','UNRESOLVED_SECURITY_FIELD',r'UNKNOWN: .+ has unresolved security field (?:ingress|type|protocol|ip_protocol|from_port|to_port|cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|bucket|acl|access_control_policy|block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets|rule|policy|tags|tags_all)'),
 ('UNKNOWN','UNRESOLVED_RESOURCE',r'UNKNOWN: .+ final resource values are unresolved'),
]

def failure_reasons(rows):
    counts=Counter()
    for row in rows:
        for failure in row.get('failures',[]):
            message=failure.get('msg') if isinstance(failure,dict) else None
            pair=('UNMAPPED','UNRECOGNIZED_POLICY_MESSAGE')
            if isinstance(message,str) and len(message)<=8192:
                pair=next(((rule,reason) for rule,reason,pattern in TEMPLATES if re.fullmatch(pattern,message)),pair)
            counts[pair]+=1
    return [{'rule_id':rule,'reason_code':reason,'count':count} for (rule,reason),count in sorted(counts.items())]


def validate_reasons(rows):
    allowed={(rule,reason) for rule,reason,_ in TEMPLATES}|{('UNMAPPED','UNRECOGNIZED_POLICY_MESSAGE')}
    if type(rows) is not list or len(rows)>len(allowed):raise ValueError('Invalid public policy reasons')
    seen=set()
    for row in rows:
        if type(row) is not dict or set(row)!={'rule_id','reason_code','count'}:raise ValueError('Invalid public policy reasons')
        pair=(row['rule_id'],row['reason_code'])
        if pair not in allowed or pair in seen or type(row['count']) is not int or not 1<=row['count']<=100000:raise ValueError('Invalid public policy reasons')
        seen.add(pair)
    return rows
