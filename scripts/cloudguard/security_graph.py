"""Bounded configuration graph facts; relationships are not exploitability."""
from pathlib import PurePosixPath, PureWindowsPath
from .plan_input import project, MAX_BYTES
from .iam import unknown
from .findings import serialize
from .risk import read_document
from .runtime import ROOT

# source field, target types, target fields, relationship, reverse, list, required
SPECS={}
def spec(types,field,targets,keys,relation,reverse=False,many=False,required=False):
    for typ in types.split():SPECS.setdefault(typ,[]).append((field,targets.split(),keys.split(),relation,reverse,many,required))
VPC='aws_vpc'; SG='aws_security_group aws_default_security_group'
spec('aws_subnet '+SG+' aws_route_table aws_internet_gateway','vpc_id',VPC,'id','MEMBER_OF_VPC',required=True)
spec('aws_instance aws_network_interface aws_nat_gateway','subnet_id','aws_subnet','id','MEMBER_OF_SUBNET',required=True)
spec('aws_instance','vpc_security_group_ids',SG,'id','USES_SECURITY_GROUP',many=True)
spec('aws_instance','security_groups',SG,'name','USES_SECURITY_GROUP',many=True)
spec('aws_network_interface aws_lb aws_alb','security_groups',SG,'id','USES_SECURITY_GROUP',many=True)
spec('aws_lb aws_alb','subnets','aws_subnet','id','MEMBER_OF_SUBNET',many=True)
spec('aws_instance','iam_instance_profile','aws_iam_instance_profile','name','USES_INSTANCE_PROFILE')
spec('aws_iam_instance_profile','role','aws_iam_role','name id','PROFILE_HAS_ROLE',required=True)
for principal in ['role','user','group']:
    spec('aws_iam_'+principal+'_policy',principal,'aws_iam_'+principal,'name id','HAS_INLINE_POLICY',reverse=True,required=True)
    typ='aws_iam_'+principal+'_policy_attachment'
    spec(typ,principal,'aws_iam_'+principal,'name id','HAS_POLICY_ATTACHMENT',reverse=True,required=True)
    spec(typ,'policy_arn','aws_iam_policy','arn','REFERENCES_POLICY',required=True)
spec('aws_route','route_table_id','aws_route_table','id','HAS_ROUTE',reverse=True,required=True)
spec('aws_route','gateway_id','aws_internet_gateway','id','ROUTE_USES_GATEWAY')
spec('aws_route','nat_gateway_id','aws_nat_gateway','id','ROUTE_USES_GATEWAY')
spec('aws_route_table_association','subnet_id','aws_subnet','id','ASSOCIATED_SUBNET')
spec('aws_route_table_association','route_table_id','aws_route_table','id','ASSOCIATED_ROUTE_TABLE',required=True)
spec('aws_route_table_association','gateway_id','aws_internet_gateway','id','ASSOCIATED_GATEWAY')
spec('aws_security_group_rule aws_vpc_security_group_ingress_rule aws_vpc_security_group_egress_rule','security_group_id',SG,'id','RULE_OF_SECURITY_GROUP',required=True)
spec('aws_security_group_rule','source_security_group_id',SG,'id','REFERENCES_SECURITY_GROUP')
spec('aws_vpc_security_group_ingress_rule aws_vpc_security_group_egress_rule','referenced_security_group_id',SG,'id','REFERENCES_SECURITY_GROUP')
for direction in ('ingress','egress'):
    spec(SG,direction+'.security_groups',SG,'id',direction.upper()+'_REFERENCES_SECURITY_GROUP',many=True)
S3={'public_access_block':'BUCKET_HAS_PAB','acl':'BUCKET_HAS_ACL','policy':'BUCKET_HAS_POLICY',
    'server_side_encryption_configuration':'BUCKET_HAS_ENCRYPTION','versioning':'BUCKET_HAS_VERSIONING',
    'logging':'BUCKET_HAS_LOGGING','lifecycle_configuration':'BUCKET_HAS_LIFECYCLE','ownership_controls':'BUCKET_HAS_OWNERSHIP'}
for suffix,relation in S3.items():spec('aws_s3_bucket_'+suffix,'bucket','aws_s3_bucket','bucket id',relation,reverse=True,required=True)
SUPPORTED=set(SPECS)|{'aws_vpc','aws_iam_role','aws_iam_user','aws_iam_group','aws_iam_policy','aws_s3_bucket'}
RELATIONS=sorted({s[3] for specs in SPECS.values() for s in specs})
SOURCE_FIELDS=sorted({s[0] for specs in SPECS.values() for s in specs})
TARGET_FIELDS=['id','name','arn','bucket']
LIMITS={'nodes':1024,'edges':8192,'unresolved':8192,'finding_associations':8192}


def require(test):
    if not test:raise ValueError("Unsupported, malformed, ambiguous or oversized graph input")


def category(typ):
    return 'IAM' if typ.startswith('aws_iam_') else 'STORAGE' if typ.startswith('aws_s3_') else 'COMPUTE' if typ=='aws_instance' else 'NETWORK'


def validate(report):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource
    def deny(uri):raise NoSuchResource(ref=uri)
    schema=read_document(ROOT/'security/security-graph.schema.json')
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema,registry=Registry(retrieve=deny)).validate(report)
    require(report['summary']=={k:len(report[k]) for k in LIMITS})
    nodes={n['id']:n for n in report['nodes']};require(len(nodes)==len(report['nodes']))
    for n in nodes.values():require(n['category']==category(n['resource_type']))
    seen=set()
    for edge in report['edges']:
        require(edge['source'] in nodes and edge['target'] in nodes)
        key=(edge['source'],edge['relationship'],edge['target']);require(key not in seen);seen.add(key)
        for proof in edge['provenance']:
            owner=nodes[edge['target'] if proof['reverse'] else edge['source']]
            target=nodes[edge['source'] if proof['reverse'] else edge['target']]
            require(any(field==proof['source_field'] and relation==edge['relationship'] and reverse==proof['reverse']
                        and target['resource_type'] in targets and proof['target_field'] in keys
                        for field,targets,keys,relation,reverse,_,_ in SPECS.get(owner['resource_type'],[])))
    require(all(r['source'] in nodes for r in report['unresolved']))
    require(all(r['node'] in nodes for r in report['finding_associations']))


def build(plan,reports=None):
    indexed,changes=project(plan)
    active={a:r for a,r in indexed.items() if r['type'] in SUPPORTED and r.get('mode','managed')=='managed'
            and changes.get(a,{}).get('change',{}).get('actions')!=['delete']}
    require(len(active)<=LIMITS['nodes'])
    for a,r in active.items():
        require(0<len(a)<=2048 and not PurePosixPath(a).is_absolute() and not PureWindowsPath(a).is_absolute())
        require(r.get('values') is None or isinstance(r['values'],dict))
    def masked(a,field):
        mask=changes.get(a,{}).get('change',{}).get('after_unknown',{})
        if mask is True:return True
        require(isinstance(mask,dict))
        return unknown(mask.get(field.split(".")[0]))
    nodes=[{'id':a,'resource_type':r['type'],'category':category(r['type']),
            'status':'PLANNED','provenance':'AFTER_STATE'} for a,r in sorted(active.items())]
    edge_map={};unresolved={}
    def pending(a,relation,field,reason):
        key=(a,relation,field,reason)
        unresolved[key]={'source':a,'relationship':relation,'source_field':field,'certainty':'UNKNOWN','reason':reason}
        require(len(unresolved)<=LIMITS['unresolved'])
    identities={}
    for a,r in active.items():
        for key in TARGET_FIELDS:
            val=(r.get('values') or {}).get(key)
            if val is None or masked(a,key):continue
            require(isinstance(val,str) and 0<len(val)<=2048)
            identities.setdefault((r['type'],key,val),set()).add(a)
    for a,r in sorted(active.items()):
        vals=r.get('values') or {}
        for field,targets,keys,relation,reverse,many,required in SPECS.get(r['type'],[]):
            if masked(a,field):pending(a,relation,field,'UNKNOWN_VALUE');continue
            value=vals.get(field)
            if '.' in field:
                direction=field.split('.')[0]
                blocks=vals.get(direction,[])
                if blocks is None:
                    pending(a,relation,field,'MISSING_VALUE');continue
                require(isinstance(blocks,list) and len(blocks)<=256)
                value=[]
                for block in blocks:
                    require(isinstance(block,dict))
                    refs=block.get('security_groups')
                    if refs is None:refs=[]
                    require(isinstance(refs,list) and len(refs)<=128)
                    value.extend(refs)
                    require(len(value)<=128)
            if value is None:
                if required or field in vals or r.get('values') is None:pending(a,relation,field,'MISSING_VALUE')
                continue
            values=value if many else [value]
            require(isinstance(values,list) and len(values)<=128)
            require(all(isinstance(v,str) and 0<len(v)<=2048 for v in values))
            for value in sorted(set(values)):
                matches={}
                for typ in targets:
                    for key in keys:
                        for candidate in identities.get((typ,key,value),[]):matches.setdefault(candidate,set()).add(key)
                if not matches:pending(a,relation,field,'NO_LOCAL_MATCH');continue
                if len(matches)>1:pending(a,relation,field,'AMBIGUOUS_MATCH');continue
                target=next(iter(matches));source,destination=(target,a) if reverse else (a,target)
                key=(source,relation,destination)
                proofs=edge_map.setdefault(key,set())
                for target_field in matches[target]:proofs.add((field,target_field,reverse))
                require(len(edge_map)<=LIMITS['edges'])
    edges=[{'source':s,'target':t,'relationship':r,'certainty':'PROVEN',
            'evidence':'EXACT_KNOWN_VALUE','provenance':[{'source_field':f,'target_field':k,'reverse':rev} for f,k,rev in sorted(proof)]}
           for (s,r,t),proof in sorted(edge_map.items())]
    associations={}
    if reports is not None:
        require(isinstance(reports,dict) and set(reports)<= {'iam','network','data'})
        from . import iam,network,data_protection
        analyzers={'iam':iam,'network':network,'data':data_protection}
        allowed={'iam':lambda t:t.startswith('aws_iam_'),'network':lambda t:category(t) in ('NETWORK','COMPUTE'),
                 'data':lambda t:t.startswith('aws_s3_')}
        for kind,report in sorted(reports.items()):
            require(len(serialize(report).encode())<=MAX_BYTES)
            analyzers[kind].validate(report)  # Never rerun/reinterpret detection.
            if kind=='data':
                require(all(c['resource'] in active and active[c['resource']]['type']=='aws_s3_bucket' for c in report['checks']))
            for finding in report['findings']:
                node=finding['resource'];require(node in active and allowed[kind](active[node]['type']))
                key=(node,report['analyzer'],finding['control_id'],finding['severity'],finding['status'])
                associations[key]={'node':node,'analyzer':report['analyzer'],'control_id':finding['control_id'],
                                   'severity':finding['severity'],'status':finding['status']}
                require(len(associations)<=LIMITS['finding_associations'])
    report={'schema_version':'1.0','builder':'cloudguard-security-graph','analysis_scope':'planned_configuration_facts',
            'nodes':nodes,'edges':edges,'unresolved':[v for _,v in sorted(unresolved.items())],
            'finding_associations':[v for _,v in sorted(associations.items())]}
    report['summary']={k:len(report[k]) for k in LIMITS};validate(report);return report
