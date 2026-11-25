"""Private owner bindings. A repository template is never an activation grant."""
import hashlib
import json
import os
from pathlib import Path
import re
import time
from cloudguard.phase6.config import require,keys,digest
from cloudguard.evidence import fingerprint
from cloudguard.runtime import ROOT

def source():
    parts=[fingerprint()]
    for p in sorted((ROOT/'backend/cloudguard_live').glob('*.py')):
        parts += [p.name,hashlib.sha256(p.read_bytes()).hexdigest()]
    for n in ('backend/serve_platform.py','backend/requirements-live.txt'):
        parts += [n,hashlib.sha256((ROOT/n).read_bytes()).hexdigest()]
    return digest(parts)

def load(path):
    original=Path(path)
    require(not original.is_symlink(),'PRIVATE_CONFIGURATION_REQUIRED')
    p=original.resolve()
    require(p.is_file() and not p.is_symlink() and not p.is_relative_to(ROOT),'PRIVATE_CONFIGURATION_REQUIRED')
    def unique(pairs):
        result={}
        for k,v in pairs:require(k not in result,'DUPLICATE_CONFIGURATION');result[k]=v
        return result
    return json.loads(p.read_text(encoding='utf-8'),object_pairs_hook=unique)

def settings(c):
    keys(c,('account_id','role_name','workspace','project','region','state_bucket','state_key','lock_table','state_kms_key','support','budget_usd','price_digest','isolation_digest'))
    require(re.fullmatch(r'[0-9]{12}',c['account_id']) and c['region']=='ap-south-1','LIVE_SCOPE_INVALID')
    require(re.fullmatch(r'cloudguard-phase6-[a-z0-9-]{3,30}',c['role_name']),'SEPARATE_PHASE6_ROLE_REQUIRED')
    for n in ('workspace','project'):require(re.fullmatch(r'[a-z][a-z0-9-]{2,23}',c[n]),'LIVE_SCOPE_INVALID')
    for n in ('state_bucket','lock_table'):require(re.fullmatch(r'[a-z][a-z0-9-]{2,62}',c[n]),'LIVE_SCOPE_INVALID')
    require(c['state_key']=='phase6/'+c['workspace']+'/terraform.tfstate','EXACT_STATE_KEY_REQUIRED')
    require(re.fullmatch(r'[1-9][0-9]{0,3}\.[0-9]{2}',c['budget_usd']),'BUDGET_INVALID')
    for n in ('price_digest','isolation_digest'):require(re.fullmatch('[a-f0-9]{64}',c[n]),'REVIEW_BINDING_REQUIRED')
    s=c['support'];keys(s,('account_id','bucket_prefix','audit_bucket','replica_bucket','kms_key','replica_kms_key','replication_role','instance_profile','ami','ami_owner','instance_role','boundary_arn'))
    require(s['account_id']==c['account_id'] and s['bucket_prefix']=='cg-live-'+c['workspace']+'-','LIVE_SCOPE_INVALID')
    for n in ('audit_bucket','replica_bucket'):require(re.fullmatch('[a-z][a-z0-9-]{2,62}',s[n]),'LIVE_SCOPE_INVALID')
    require(len({c['state_bucket'],s['audit_bucket'],s['replica_bucket']})==3,'SUPPORT_MUST_BE_SEPARATE')
    for key,region,value in [('state_kms_key','ap-south-1',c['state_kms_key']),('kms_key','ap-south-1',s['kms_key']),('replica_kms_key','ap-south-2',s['replica_kms_key'])]:
        require(re.fullmatch('arn:aws:kms:'+region+':'+c['account_id']+r':key/[a-f0-9-]{36}',value),'EXACT_KMS_KEY_REQUIRED')
    for n,kind in [('replication_role','role'),('boundary_arn','policy')]:
        require(re.fullmatch('arn:aws:iam::'+c['account_id']+':'+kind+r'/cloudguard-phase6-[A-Za-z0-9-]{3,64}',s[n]),'EXACT_IAM_BINDING_REQUIRED')
    for n in ('instance_role','instance_profile'):require(re.fullmatch('cloudguard-phase6-[A-Za-z0-9-]{3,64}',s[n]),'EXACT_IAM_BINDING_REQUIRED')
    require(re.fullmatch('ami-[a-f0-9]{17}',s['ami']) and re.fullmatch('[0-9]{12}',s['ami_owner']),'APPROVED_AMI_REQUIRED')
    return c

class Authority:
    def __init__(self,c,path,clock=time.time,source_fn=source,loader=load):
        self.c=settings(c);self.path=path;self.clock=clock;self.source=source_fn;self.loader=loader
    def check(self,operation):
        require(operation in ('read','plan','deploy','delete'),'INVALID_OPERATION')
        a=self.loader(self.path)
        keys(a,('status','approved_by','not_before','expires_at','configuration_digest','source_digest','allow_read','allow_state_locking','allow_deploy','allow_delete','isolation_digest'))
        require(a['status']=='APPROVED' and type(a['approved_by']) is str and 1<=len(a['approved_by'])<=80,'OWNER_ACTIVATION_REQUIRED')
        for n in ('allow_read','allow_state_locking','allow_deploy','allow_delete'):require(type(a[n]) is bool,'OWNER_ACTIVATION_REQUIRED')
        require(type(a['not_before']) in (int,float) and type(a['expires_at']) in (int,float) and 0<a['expires_at']-a['not_before']<=604800 and a['not_before']<=self.clock()<a['expires_at'],'AUTHORIZATION_EXPIRED')
        require(a['configuration_digest']==digest(self.c) and a['source_digest']==self.source() and a['isolation_digest']==self.c['isolation_digest'],'AUTHORIZATION_BINDING_INVALID')
        require(a['allow_read'] and (operation=='read' or a['allow_state_locking']),'READ_OR_LOCKING_NOT_AUTHORIZED')
        if operation in ('deploy','delete'):require(a['allow_deploy'],'DEPLOYMENT_NOT_AUTHORIZED')
        if operation=='delete':require(a['allow_delete'],'DELETION_NOT_AUTHORIZED')
        return digest(a)

    def credentials(self,environ=None):
        e=os.environ if environ is None else environ
        require(all(e.get(n) for n in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','CLOUDGUARD_AWS_EXPIRES_AT')),'TEMPORARY_CREDENTIALS_REQUIRED')
        require(self.clock()+120<float(e['CLOUDGUARD_AWS_EXPIRES_AT'])<=self.clock()+43200,'TEMPORARY_CREDENTIALS_EXPIRED')
        require(not any(e.get(n) for n in e if n.startswith('AWS_ENDPOINT_URL') or n in ('AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_PROFILE','AWS_DEFAULT_PROFILE','AWS_CONFIG_FILE','AWS_SHARED_CREDENTIALS_FILE','AWS_CA_BUNDLE','AWS_DATA_PATH','BOTO_CONFIG')),'ENDPOINT_OR_ROLE_OVERRIDE_DENIED')
        return {k:e[k] for k in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')}
