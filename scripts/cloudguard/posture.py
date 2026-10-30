"""Informational integration of explicit reports; no new security authority."""
from copy import deepcopy
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from . import iam,network,data_protection,security_graph
from .findings import serialize
from .risk import read_document
from .runtime import ROOT
from .integration import output_directory,write_file

ANALYZERS={'iam':iam,'network':network,'data':data_protection,'graph':security_graph}
SCHEMAS={'private':'cloud-posture-report','summary':'cloud-posture-summary','completion':'phase4-completion'}
MAX_INPUT=8*1024*1024
MAX_FINDINGS=4096
MAX_PRIVATE=16*1024*1024
MAX_PUBLIC=4096
LEVELS=('NONE','LOW','MEDIUM','HIGH','CRITICAL')
IDENTITY={'iam':('resource','policy_kind','statement_index','control_id'),
          'network':('resource','direction','rule_index','address_family','control_id','service_port'),
          'data':('resource','category','control_id')}


def require(test):
    if not test:raise ValueError('Invalid, inconsistent or oversized posture input')


def schema_validate(value,kind):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource
    def deny(uri):raise NoSuchResource(ref=uri)
    schema=read_document(ROOT/'security'/(SCHEMAS[kind]+'.schema.json'))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema,registry=Registry(retrieve=deny)).validate(value)


def validate_inputs(reports):
    require(type(reports) is dict and set(reports)==set(ANALYZERS))
    for kind,report in reports.items():
        require(len(serialize(report).encode())<=MAX_INPUT)
        ANALYZERS[kind].validate(report)
        if kind!='graph':
            require(len(report['findings'])<=MAX_FINDINGS)
            seen=set()
            for finding in report['findings']:
                identity=tuple(finding[k] for k in IDENTITY[kind])
                require(identity not in seen);seen.add(identity)
    graph=reports['graph'];nodes={n['id']:n for n in graph['nodes']}
    require(all(not PurePosixPath(a).is_absolute() and not PureWindowsPath(a).is_absolute() for a in nodes))
    associations=set()
    for kind in ('iam','network','data'):
        for finding in reports[kind]['findings']:
            address=finding['resource'];require(address in nodes)
            typ=nodes[address]['resource_type']
            require(typ.startswith('aws_iam_') if kind=='iam' else typ.startswith('aws_s3_') if kind=='data' else security_graph.category(typ) in ('NETWORK','COMPUTE'))
            associations.add((address,reports[kind]['analyzer'],finding['control_id'],finding['severity'],finding['status']))
    actual=[(a['node'],a['analyzer'],a['control_id'],a['severity'],a['status']) for a in graph['finding_associations']]
    require(len(actual)==len(set(actual)) and set(actual)==associations)
    checks=reports['data']['checks'];seen=set()
    for check in checks:
        key=(check['resource'],check['category']);require(key not in seen);seen.add(key)
        require(check['resource'] in nodes and nodes[check['resource']]['resource_type']=='aws_s3_bucket')
    expected={(a,c) for a,n in nodes.items() if n['resource_type']=='aws_s3_bucket' for c in data_protection.CATEGORIES}
    require(seen==expected)
    unresolved=[serialize(r) for r in graph['unresolved']]
    require(len(unresolved)==len(set(unresolved)))


def domain(report,unknown_context=0):
    rows=report['findings'];counts={s.lower():sum(r['severity']==s for r in rows) for s in LEVELS[1:]}
    counts['unknown']=sum(r['severity']=='UNKNOWN' for r in rows)
    known=[s for s in LEVELS[1:] if counts[s.lower()]]
    highest=max(known,key=LEVELS.index) if known else 'UNKNOWN' if counts['unknown'] or unknown_context else 'NONE'
    return {'finding_count':len(rows),'severity_counts':counts,'category':highest,
            'unknown_context_count':unknown_context,
            'requires_review':bool(unknown_context or counts['unknown'] or any(r['requires_review'] for r in rows))}


def prepare(inputs):
    reports=deepcopy(inputs);validate_inputs(reports)
    fingerprints={kind:hashlib.sha256(serialize(report).encode('utf-8')).hexdigest() for kind,report in sorted(reports.items())}
    context={'same_plan':'UNKNOWN','freshness':'UNKNOWN','authenticity':'UNKNOWN',
             'fingerprint_algorithm':'SHA-256','fingerprint_basis':'canonical-report-json','report_fingerprints':fingerprints}
    domains={kind:domain(reports[kind],sum(c['state']=='UNKNOWN' for c in reports['data']['checks']) if kind=='data' else 0) for kind in ('iam','network','data')}
    graph=reports['graph']
    domains['graph']={**graph['summary'],'requires_review':bool(graph['unresolved'])}
    known=[d['category'] for k,d in domains.items() if k!='graph' and d['category'] in LEVELS[1:]]
    overall={'category':max(known,key=LEVELS.index) if known else 'UNKNOWN' if any(d['category']=='UNKNOWN' for k,d in domains.items() if k!='graph') else 'NONE',
             'requires_review':True}  # Context cannot be verified from these report formats.
    private={'schema_version':'1.0','integrator':'cloudguard-posture','informational_only':True,
             'analysis_context':context,'domains':domains,'overall':overall,
             'findings':{kind:deepcopy(reports[kind]['findings']) for kind in ('iam','network','data')},
             'data_checks':deepcopy(reports['data']['checks']),
             'unresolved':deepcopy(graph['unresolved']),'finding_associations':deepcopy(graph['finding_associations'])}
    summary={'schema_version':'1.0','integrator':'cloudguard-posture','informational_only':True,'phase':'4',
             'completion_requirement':'VALID_RECEIPT_REQUIRED','context_status':'UNKNOWN',
             'domains':{k:deepcopy(domains[k]) for k in ('iam','network','data')},
             'graph':{'unresolved_count':len(graph['unresolved']),'requires_review':bool(graph['unresolved'])},'overall':deepcopy(overall)}
    receipt={'schema_version':'1.0','phase':'4','status':'COMPLETE','informational_only':True,
             'components':{k:'COMPLETE' for k in ('4.1','4.2','4.3','4.4','4.5')},'phase5_status':'NOT_STARTED',
             'context_status':'UNKNOWN','validation':{k:'PASS' for k in ('input_schemas','cross_report_consistency','output_schemas','byte_reproduction')},'execution_mode':'offline'}
    for kind,value in [('private',private),('summary',summary),('completion',receipt)]:schema_validate(value,kind)
    require(len(serialize(private).encode())<=MAX_PRIVATE)
    require(all(len(serialize(value).encode())<=MAX_PUBLIC for value in (summary,receipt)))
    return private,summary,receipt


def publish(inputs,private_dir,public_dir,root=ROOT):
    private_dir=output_directory(private_dir,root/'reports/private')
    public_dir=output_directory(public_dir,root/'reports/sanitized')
    reports=deepcopy(inputs)
    first=prepare(reports);require(tuple(map(serialize,first))==tuple(map(serialize,prepare(reports))))
    payloads=[(private_dir/'posture.json',serialize(first[0]),'private'),
              (public_dir/'posture-summary.json',serialize(first[1]),'summary')]
    created_dirs=[];created_files=[];complete=False
    try:
        for directory in (private_dir,public_dir):
            directory.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            directory.mkdir(mode=0o700);created_dirs.append(directory)
        for path,text,kind in payloads:
            created_files.append(path);write_file(path,text)
            schema_validate(read_document(path),kind)
            require(path.read_bytes()==text.encode('utf-8'))
        # Completion exists only after validation, reproduction and byte readback.
        temporary=public_dir/'.phase4-completion.tmp';created_files.append(temporary)
        text=serialize(first[2]);write_file(temporary,text)
        schema_validate(read_document(temporary),'completion');require(temporary.read_bytes()==text.encode('utf-8'))
        final=public_dir/'phase4-completion.json';require(not final.exists())
        temporary.rename(final);created_files.append(final);complete=True
    finally:
        if not complete:
            for path in reversed(created_files):path.unlink(missing_ok=True)
            for directory in reversed(created_dirs):directory.rmdir()
    return first[1]
