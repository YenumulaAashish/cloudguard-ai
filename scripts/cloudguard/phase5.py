"""Integrate an explicit plan locally; publication is completion-last and value-free."""
import json
from . import posture, integration, public_findings
from .runtime import ROOT
from .findings import serialize
from .risk import read_document

def validate_bundle(bundle):
    if type(bundle) is not dict or set(bundle) != {'version','source','pr','phase3','posture','phase4','findings'} or bundle['version'] != '1.1' or bundle['source'] not in public_findings.SOURCES:
        raise ValueError('Invalid dashboard bundle')
    integration.schema_validate(bundle['pr'], 'summary')
    integration.validate_summary(bundle['pr'])
    integration.schema_validate(bundle['phase3'], 'manifest')
    posture.schema_validate(bundle['posture'], 'summary')
    posture.schema_validate(bundle['phase4'], 'completion')
    catalog = public_findings.validate(bundle['findings'])
    if catalog['source'] != bundle['source'] or bundle['pr']['advisory']['mode'] != bundle['phase3']['advisory_mode']:
        raise ValueError('Inconsistent dashboard source')
    if bundle['source'] != 'AUTHENTICATED_PLAN' and bundle['pr']['policy']['opa_conftest'] != 'UNKNOWN':
        raise ValueError('Unsupported real-plan verdict')
    domains = bundle['posture']['domains']
    if catalog['total_count'] != sum(d['finding_count'] for d in domains.values()):
        raise ValueError('Inconsistent dashboard counts')
    for name, d in domains.items():
        if sum(d['severity_counts'].values()) != d['finding_count']:
            raise ValueError('Inconsistent severity counts')
        counts = {level: sum(f['domain'] == name and f['severity'].lower() == level for f in catalog['findings']) for level in d['severity_counts']}
        if any(counts[level] > d['severity_counts'][level] for level in counts) or (catalog['omitted_count'] == 0 and counts != d['severity_counts']):
            raise ValueError('Inconsistent finding projection')
    return bundle


def prepare(plan, source, scanner_inputs):
    reports = public_findings.analyze(plan)
    private, summary, receipt = posture.prepare(reports)
    chain, phase3_private, phase3_public = integration.prepare(scanner_inputs, evidence=source == 'AUTHENTICATED_PLAN')
    bundle = {'version': '1.1', 'source': source, 'pr': chain['summary'],
              'phase3': json.loads(phase3_public['phase3-evidence.json']),
              'posture': summary, 'phase4': receipt, 'findings': public_findings.project(reports, source)}
    # Reuse every existing contract. New catalog supplements rather than changes them.
    integration.schema_validate(bundle['pr'], 'summary')
    integration.schema_validate(bundle['phase3'], 'manifest')
    posture.schema_validate(summary, 'summary'); posture.schema_validate(receipt, 'completion')
    public_findings.validate(bundle['findings'])
    validate_bundle(bundle)
    text = serialize(bundle)
    if len(text.encode()) > 131072:
        raise ValueError('Public bundle too large')
    lines = ['# CloudGuard Phase 4 posture', '', 'Informational only; deterministic gates remain authoritative.',
             'Source: ' + source, 'Context / authenticity / freshness: UNKNOWN',
             'Overall category: ' + summary['overall']['category'], 'Review required: YES', '']
    for name, d in summary['domains'].items():
        lines.append(f"- {name}: {d['category']}; findings {d['finding_count']}; unknown findings {d['severity_counts']['unknown']}; review {d['requires_review']}")
    lines += ['', 'Graph relationships do not prove runtime reachability or exploitability.',
              'No resource identities, topology, policies or private fingerprints are published.']
    return {**phase3_private, 'posture.json': serialize(private)}, {
        'dashboard.json': text, 'posture-summary.json': serialize(summary),
        'phase4-completion.json': serialize(receipt), 'posture-summary.md': '\n'.join(lines) + '\n'}


def publish(plan_path, private_dir, public_dir, source, scanner_inputs, root=ROOT):
    if source not in public_findings.SOURCES:
        raise ValueError('Unsupported source')
    if plan_path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Plan too large')
    plan = read_document(plan_path)
    first = prepare(plan, source, scanner_inputs)
    if first != prepare(plan, source, scanner_inputs):
        raise ValueError('Reproduction failed')
    private_dir = integration.output_directory(private_dir, root / 'reports/private')
    public_dir = integration.output_directory(public_dir, root / 'reports/sanitized')
    created = []; directories = []
    try:
        for directory in (private_dir, public_dir):
            directory.parent.mkdir(parents=True, exist_ok=True)
            directory.mkdir(mode=0o700); directories.append(directory)
        for directory, values in zip((private_dir, public_dir), first):
            for name, text in values.items():
                if name == 'dashboard.json':
                    continue
                path = directory / name; created.append(path); integration.write_file(path, text)
                if path.read_bytes() != text.encode():
                    raise ValueError('Readback failed')
        # Only the final bundle is eligible for consumption/upload; write it last.
        temporary = public_dir / '.dashboard.tmp'; created.append(temporary)
        integration.write_file(temporary, first[1]['dashboard.json'])
        if temporary.read_bytes() != first[1]['dashboard.json'].encode():
            raise ValueError('Readback failed')
        final = public_dir / 'dashboard.json'; temporary.rename(final); created.append(final)
    except Exception:
        for path in reversed(created): path.unlink(missing_ok=True)
        for directory in reversed(directories): directory.rmdir()
        raise
    return json.loads(first[1]['dashboard.json'])
