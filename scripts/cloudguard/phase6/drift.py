"""FR-4 / O4: deterministic drift classification, never inferred from missing data."""
from copy import deepcopy
from .config import digest

COMPUTED={'id','arn','tags_all'}
FIELD_CODES={'cidr_block':'NETWORK_CIDR','map_public_ip_on_launch':'PUBLIC_IP','associate_public_ip_address':'PUBLIC_IP',
 'metadata_options':'INSTANCE_METADATA','root_block_device':'VOLUME_PROTECTION','ingress':'NETWORK_RULES','egress':'NETWORK_RULES',
 'rule':'CONTROL_CONFIGURATION','policy':'POLICY','tags':'TAGS','versioning_configuration':'VERSIONING',
 'block_public_acls':'PUBLIC_ACCESS_BLOCK','block_public_policy':'PUBLIC_ACCESS_BLOCK','ignore_public_acls':'PUBLIC_ACCESS_BLOCK','restrict_public_buckets':'PUBLIC_ACCESS_BLOCK'}

def detect(declared,snapshot,lineage,serial,now,max_age=300):
    valid=(type(snapshot) is dict and snapshot.get('complete') is True and snapshot.get('lineage')==lineage and
        type(snapshot.get('serial')) is int and snapshot.get('serial')==serial and type(snapshot.get('captured_at')) in (int,float) and
        0<=now-snapshot['captured_at']<=max_age and type(snapshot.get('resources')) is dict)
    if not valid:return {'status':'UNKNOWN','changes':[],'reason':'OBSERVATION_UNAVAILABLE_OR_STALE'}
    observed=snapshot['resources'];changes=[]
    for address in sorted(set(declared)|set(observed)):
        d=declared.get(address);o=observed.get(address)
        if d is None:
            if type(o) is not dict:
                changes.append({'address':address,'type':'unsupported','kind':'UNKNOWN','fields':[]});continue
            changes.append({'address':address,'type':o.get('type','unsupported'),'kind':'UNMANAGED','fields':[]});continue
        if o is None:
            changes.append({'address':address,'type':d['type'],'kind':'MISSING','fields':[]});continue
        if type(o) is not dict or o.get('owned') is not True or o.get('type')!=d['type'] or type(o.get('values')) is not dict or o.get('unresolved'):
            changes.append({'address':address,'type':d['type'],'kind':'UNKNOWN','fields':[]});continue
        expected=d['values'];actual=o['values'];extra=set(actual)-set(expected)-COMPUTED
        fields=sorted({FIELD_CODES.get(k,'OTHER_MANAGED_CONFIGURATION') for k in expected if k not in actual or actual[k]!=expected[k]})
        if extra:changes.append({'address':address,'type':d['type'],'kind':'UNKNOWN','fields':['UNSUPPORTED_OBSERVED_ATTRIBUTES']})
        elif fields:changes.append({'address':address,'type':d['type'],'kind':'CHANGED','fields':fields})
    status='UNKNOWN' if any(c['kind']=='UNKNOWN' for c in changes) else 'DRIFTED' if changes else 'IN_SYNC'
    return {'status':status,'changes':changes,'reason':'CONFIGURATION_COMPARISON_ONLY'}
