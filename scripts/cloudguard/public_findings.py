"""Explicit minimal finding projection. No source prose, identity or topology leaves here."""
from copy import deepcopy
import json
from .runtime import ROOT
from . import iam, network, data_protection, security_graph, posture

MAX_ROWS = 256
SOURCES = ('SYNTHETIC', 'OFFLINE', 'AUTHENTICATED_PLAN')
RESOURCE_TYPES = sorted(security_graph.SUPPORTED)


def validate(value):
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / 'security/public-findings.schema.json').read_text())
    Draft202012Validator(schema).validate(value)
    rows = value['findings']
    if value['total_count'] != len(rows) + value['omitted_count'] or len({f['id'] for f in rows}) != len(rows):
        raise ValueError('Invalid public findings')
    for f in rows:
        prefix = {'iam': 'CGA_IAM_', 'network': 'CGA_NET_', 'data': 'CGA_DATA_'}[f['domain']]
        if not f['control_id'].startswith(prefix):
            raise ValueError('Mismatched domain')
    return deepcopy(value)


def project(reports, source):
    posture.validate_inputs(reports)
    types = {node['id']: node['resource_type'] for node in reports['graph']['nodes']}
    rows = []
    for domain in ('iam', 'network', 'data'):
        for f in reports[domain]['findings']:
            # Sort privately before projecting. Addresses affect ordering, never output.
            rows.append((domain, f))
    rows.sort(key=lambda pair: (pair[0], pair[1]['control_id'], pair[1]['resource']))
    public = []
    for index, (domain, f) in enumerate(rows[:MAX_ROWS]):
        public.append({'id': f'finding-{index:04d}', 'domain': domain,
                       'control_id': f['control_id'], 'resource_type': types[f['resource']],
                       'severity': f['severity'], 'status': f['status'], 'requires_review': f['requires_review']})
    return validate({'schema_version': '1.0', 'source': source, 'context_status': 'UNKNOWN',
                     'informational_only': True, 'total_count': len(rows),
                     'omitted_count': len(rows) - len(public), 'findings': public})


def analyze(plan):
    reports = {'iam': iam.analyze(plan), 'network': network.analyze(plan), 'data': data_protection.analyze(plan)}
    reports['graph'] = security_graph.build(plan, reports)
    return reports
