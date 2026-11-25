"""Real adapters under fake AWS/process I/O. No live API or deployment in this suite."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'backend')]
from cloudguard.phase6.config import generate,render_hcl,digest
from cloudguard.phase6.http import Service,valid_response
from cloudguard_live.settings import Authority,settings
from cloudguard_live.aws import AWS
from cloudguard_live.native import Native
from cloudguard_live.engine import LiveEngine,plan_scope
from cloudguard_live.pricing import estimate,METERS,UNITS
NOW=1795670400

def configuration():return json.loads((ROOT/'tests/fixtures/phase6/configuration.json').read_text())|{'budget_usd':'100.00'}
def bindings():
    c=json.loads((ROOT/'security/phase6-live-settings.template.json').read_text())
    support=generate(configuration())[0] # Explicit test identities, never real owner bindings.
    account='111122223333';key=lambda r,n:'arn:aws:kms:'+r+':'+account+':key/00000000-0000-0000-0000-00000000000'+str(n)
    c.update(account_id=account,state_bucket='cg-test-state',lock_table='cg-test-lock',state_kms_key=key('ap-south-1',3),price_digest='a'*64,isolation_digest='b'*64,budget_usd='100.00')
    c['support'].update(account_id=account,audit_bucket='cg-test-audit',replica_bucket='cg-test-replica',kms_key=key('ap-south-1',1),replica_kms_key=key('ap-south-2',2),replication_role='arn:aws:iam::'+account+':role/cloudguard-phase6-replication',instance_profile='cloudguard-phase6-empty',instance_role='cloudguard-phase6-empty',boundary_arn='arn:aws:iam::'+account+':policy/cloudguard-phase6-deny-all',ami='ami-0123456789abcdef0',ami_owner=account)
    return c

def book():return {'kind':'AWS_REVIEWED_EXPORT','currency':'USD','regions':['ap-south-1','ap-south-2'],'as_of':NOW-1,'expires_at':NOW+3600,'rates':{k:{'usd_per_unit':'0.001','source':'https://aws.amazon.com/test-price-fixture','unit':UNITS[k],'sku':k,'reviewed':True} for k in METERS}}
def grant(c):return {'status':'APPROVED','approved_by':'test-only','not_before':NOW-1,'expires_at':NOW+3600,'configuration_digest':digest(c),'source_digest':'test-source','allow_read':True,'allow_state_locking':True,'allow_deploy':True,'allow_delete':True,'isolation_digest':c['isolation_digest']}
class Fakes:
    def setUp(self):
        self.time=[NOW];self.c=bindings();self.b=book();self.c['price_digest']=digest(self.b);self.g=grant(self.c)
        self.auth=Authority(self.c,'unused',lambda:self.time[0],lambda:'test-source',lambda p:deepcopy(self.g))
        self.auth.credentials=lambda environ=None:{'AWS_ACCESS_KEY_ID':'test','AWS_SECRET_ACCESS_KEY':'private-canary','AWS_SESSION_TOKEN':'test-session'}

class AuthorizationTests(Fakes,unittest.TestCase):
    def test_exact_closed_bindings_and_legacy_role_rejected(self):
        self.assertEqual(settings(self.c),self.c)
        for key,val in [('region','us-east-1'),('role_name','cloudguard-ai-plan'),('state_key','other/state'),('price_digest',''),('workspace','${bad}')]:
            bad=deepcopy(self.c);bad[key]=val
            with self.subTest(key=key),self.assertRaises(ValueError):settings(bad)
    def test_grant_positive_and_operation_separation(self):
        self.auth.check('deploy');self.g['allow_deploy']=False;self.auth.check('plan')
        with self.assertRaises(ValueError):self.auth.check('deploy')
        self.g['allow_state_locking']=False;self.auth.check('read')
        with self.assertRaises(ValueError):self.auth.check('plan')
    def test_each_missing_expired_and_changed_binding_fails_closed(self):
        for key,value in [('status','NOT_APPROVED'),('approved_by',None),('not_before',NOW+1),('expires_at',NOW),('expires_at',NOW+604801),('source_digest','other'),('configuration_digest','other'),('isolation_digest','other'),('allow_read',False),('allow_state_locking','yes')]:
            old=deepcopy(self.g);self.g[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.auth.check('plan')
            self.g=old
        for key in tuple(self.g):
            old=self.g.pop(key)
            with self.subTest(missing=key),self.assertRaises(ValueError):self.auth.check('read')
            self.g[key]=old
    def test_temporary_credentials_expiry_no_default_chain_or_overrides(self):
        good={'AWS_ACCESS_KEY_ID':'test','AWS_SECRET_ACCESS_KEY':'test','AWS_SESSION_TOKEN':'test','CLOUDGUARD_AWS_EXPIRES_AT':str(NOW+3600)}
        actual=Authority.credentials
        self.assertIn('AWS_SESSION_TOKEN',actual(self.auth,good))
        for key in good:
            e=dict(good);e.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):actual(self.auth,e)
        for e in [dict(good,CLOUDGUARD_AWS_EXPIRES_AT=str(NOW+119)),dict(good,AWS_ENDPOINT_URL='https://evil'),dict(good,AWS_ROLE_ARN='other'),dict(good,AWS_ENDPOINT_URL_EC2='https://evil'),dict(good,AWS_CONFIG_FILE='unreviewed'),dict(good,AWS_PROFILE='other')]:
            with self.assertRaises(ValueError):actual(self.auth,e)
    def test_no_aws_factory_call_without_read_authorization(self):
        called=[];aws=AWS(self.auth,lambda *args:called.append(args));self.g['allow_read']=False
        with self.assertRaises(ValueError):aws.client('sts')
        self.assertEqual(called,[])
    def test_import_and_construction_have_no_sdk_or_process_side_effect(self):
        with patch('subprocess.run',side_effect=AssertionError('process called')):
            AWS(self.auth);Native(self.auth,None)
    def test_repository_activation_is_inert(self):
        t=json.loads((ROOT/'security/phase6-live-authorization.template.json').read_text());self.assertEqual(t['status'],'NOT_APPROVED')
        self.assertFalse(any(t[k] for k in ('allow_read','allow_state_locking','allow_deploy','allow_delete')))

class PriceTests(Fakes,unittest.TestCase):
    def test_reviewed_export_and_conservative_hours(self):
        c=configuration();a=estimate(c,self.b,self.c,NOW);self.assertEqual(a['status'],'PASS');c['ec2']['hours']=730
        self.assertEqual(a,estimate(c,self.b,self.c,NOW));self.assertNotIn('private',str(a))
    def test_budget_exceeded_unknown_provenance_missing_rate_or_stale(self):
        c=configuration();c['budget_usd']='0.01';self.assertEqual(estimate(c,self.b,self.c,NOW)['status'],'FAIL')
        for change in [lambda b:b.update(kind='MOCK_ONLY'),lambda b:b.update(expires_at=NOW),lambda b:b['rates'].pop('kms_key_month'),lambda b:b['rates']['kms_request'].update(usd_per_unit='NaN'),lambda b:b['rates']['kms_request'].update(reviewed=False),lambda b:b['rates']['kms_request'].update(unit='1000 requests')]:
            b=deepcopy(self.b);change(b);cfg=deepcopy(self.c);cfg['price_digest']=digest(b)
            self.assertEqual(estimate(configuration(),b,cfg,NOW)['status'],'UNKNOWN')
        self.c['price_digest']='f'*64;self.assertEqual(estimate(configuration(),self.b,self.c,NOW)['status'],'UNKNOWN')

class SDKDouble:
    def __init__(self,c):self.c=c;self.bad=None;self.calls=[]
    def __getattr__(self,api):
        def call(**kw):
            self.calls.append((api,kw));c=self.c;s=c['support'];b=kw.get('Bucket');region='ap-south-2' if b==s['replica_bucket'] else 'ap-south-1'
            key=c['state_kms_key'] if b==c['state_bucket'] else s['replica_kms_key']
            policy={'Statement':[{'Effect':'Deny','Principal':'*','Action':'s3:*','Resource':['arn:aws:s3:::'+str(b),'arn:aws:s3:::'+str(b)+'/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}]+[{'Effect':'Allow','Principal':{'Service':x},'Condition':{'StringEquals':{'aws:SourceAccount':c['account_id']}}} for x in ('logging.s3.amazonaws.com','delivery.logs.amazonaws.com')]}
            d={'get_caller_identity':{'Account':c['account_id'],'Arn':'arn:aws:sts::'+c['account_id']+':assumed-role/'+c['role_name']+'/test'},'get_bucket_location':{'LocationConstraint':region},'get_bucket_versioning':{'Status':'Enabled'},'get_public_access_block':{'PublicAccessBlockConfiguration':dict(BlockPublicAcls=True,BlockPublicPolicy=True,IgnorePublicAcls=True,RestrictPublicBuckets=True)},'get_bucket_encryption':{'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256' if b==s['audit_bucket'] else 'aws:kms','KMSMasterKeyID':key}}]}},'get_bucket_ownership_controls':{'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]}},'get_bucket_policy_status':{'PolicyStatus':{'IsPublic':False}},'get_bucket_policy':{'Policy':json.dumps(policy)},'get_bucket_logging':{},'describe_key':{'KeyMetadata':{'Arn':kw.get('KeyId'),'KeyManager':'CUSTOMER','KeyState':'Enabled'}},'get_key_rotation_status':{'KeyRotationEnabled':True},'describe_table':{'Table':{'TableStatus':'ACTIVE','KeySchema':[{'AttributeName':'LockID','KeyType':'HASH'}],'AttributeDefinitions':[{'AttributeName':'LockID','AttributeType':'S'}]}},'get_instance_profile':{'InstanceProfile':{'Roles':[{'RoleName':s['instance_role']}]}},'get_role':{'Role':{'PermissionsBoundary':{'PermissionsBoundaryArn':s['boundary_arn']}}},'get_policy':{'Policy':{'DefaultVersionId':'v1'}},'get_policy_version':{'PolicyVersion':{'Document':{'Statement':[{'Effect':'Deny','Action':'*','Resource':'*'}]}}},'list_role_policies':{'PolicyNames':[]},'list_role_attached_policies':{'AttachedPolicies':[]},'describe_images':{'Images':[{'State':'available','Architecture':'x86_64'}]},'list_objects_v2':{'KeyCount':0},'list_object_versions':{},'list_multipart_uploads':{},'head_bucket':{},'describe_vpcs':{'Vpcs':[{'VpcId':'vpc-canary'}]},'describe_instances':{'Reservations':[{'Instances':[{'InstanceId':'i-canary','State':{'Name':'running'}}]}]}}
            if api=='get_role':
                replication=kw['RoleName']==s['replication_role'].rsplit('/',1)[1]
                d[api]['Role']['AssumeRolePolicyDocument']={'Statement':[{'Effect':'Allow','Principal':{'Service':'s3.amazonaws.com' if replication else 'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]}
                if replication:d[api]['Role']['Arn']=s['replication_role']
            if api=='list_role_policies' and kw['RoleName']==s['replication_role'].rsplit('/',1)[1]:d[api]={'PolicyNames':['replication']}
            if api=='get_role_policy':
                src='arn:aws:s3:::'+s['bucket_prefix']+c['project']+'-'+digest(c['project'])[:8];dst='arn:aws:s3:::'+s['replica_bucket']
                d[api]={'PolicyDocument':{'Statement':[{'Effect':'Allow','Action':actions,'Resource':resource} for actions,resource in [(['s3:GetReplicationConfiguration','s3:ListBucket'],src),(['s3:GetObjectVersionForReplication','s3:GetObjectVersionAcl','s3:GetObjectVersionTagging'],src+'/*'),(['s3:ReplicateObject','s3:ReplicateTags'],dst+'/*'),('kms:Decrypt',s['kms_key']),('kms:Encrypt',s['replica_kms_key'])]]}}
            value=deepcopy(d[api])
            if self.bad and self.bad[0]==api:value=self.bad[1]
            return value
        return call

class SDKTests(Fakes,unittest.TestCase):
    def test_live_support_verification_positive_then_revoked_freshness(self):
        sdk=SDKDouble(self.c);aws=AWS(self.auth,lambda *a:sdk);self.assertEqual(aws.verify()['status'],'VERIFIED');self.assertTrue(aws.fresh())
        self.time[0]+=301;self.assertFalse(aws.fresh())
        self.assertNotIn('private-canary',str(aws.verify()))
    def test_real_sdk_client_construction_uses_explicit_credentials_no_profile_or_endpoint_fallback(self):
        import boto3
        with patch.object(boto3,'Session') as session:
            AWS(self.auth).client('ec2')
            kwargs=session.call_args.kwargs;self.assertIn('aws_session_token',kwargs)
            core=kwargs['botocore_session'];self.assertEqual(core.get_config_variable('config_file'),__import__('os').devnull)
            cfg=session.return_value.client.call_args.kwargs['config'];self.assertTrue(cfg.ignore_configured_endpoint_urls);self.assertEqual(cfg.retries,{'total_max_attempts':1});self.assertEqual(cfg.proxies,{})
    def test_each_security_dependency_negative_fails_and_clears_verified_binding(self):
        failures=[('get_caller_identity',{'Account':'000000000000','Arn':'other'}),('get_bucket_location',{'LocationConstraint':'us-east-1'}),('get_bucket_versioning',{'Status':'Suspended'}),('get_public_access_block',{'PublicAccessBlockConfiguration':{}}),('get_bucket_encryption',{'ServerSideEncryptionConfiguration':{'Rules':[]}}),('get_bucket_ownership_controls',{'OwnershipControls':{'Rules':[]}}),('get_bucket_policy_status',{'PolicyStatus':{'IsPublic':True}}),('get_bucket_policy',{'Policy':'{"Statement":[]}'}),('get_bucket_logging',{'LoggingEnabled':{'TargetBucket':'self'}}),('describe_key',{'KeyMetadata':{'Arn':'other','KeyManager':'AWS','KeyState':'Disabled'}}),('get_key_rotation_status',{'KeyRotationEnabled':False}),('describe_table',{'Table':{'TableStatus':'DELETING'}}),('get_instance_profile',{'InstanceProfile':{'Roles':[]}}),('get_role',{'Role':{}}),('get_policy_version',{'PolicyVersion':{'Document':{'Statement':[]}}}),('list_role_policies',{'PolicyNames':['unwanted']}),('list_role_attached_policies',{'AttachedPolicies':[{'PolicyName':'unwanted'}]}),('describe_images',{'Images':[]}),('get_role_policy',{'PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}})]
        for failure in failures:
            sdk=SDKDouble(self.c);aws=AWS(self.auth,lambda *a:sdk);aws.verify();sdk.bad=failure
            with self.subTest(api=failure[0]),self.assertRaises((ValueError,KeyError)):aws.verify()
            self.assertIsNone(aws.binding)
    def test_versioned_or_pending_data_blocks_empty_bucket_test(self):
        sdk=SDKDouble(self.c);aws=AWS(self.auth,lambda *a:sdk);aws.empty_bucket('cg-test')
        for failure in [('list_objects_v2',{'KeyCount':1}),('list_object_versions',{'Versions':[{}]}),('list_object_versions',{'DeleteMarkers':[{}]}),('list_object_versions',{'IsTruncated':True}),('list_multipart_uploads',{'Uploads':[{}]})]:
            sdk.bad=failure
            with self.subTest(api=failure[0]),self.assertRaises(ValueError):aws.empty_bucket('cg-test')
    def test_inventory_never_uses_tags_as_ownership_and_only_targeted_s3(self):
        sdk=SDKDouble(self.c);aws=AWS(self.auth,lambda *a:sdk)
        rows=aws.inventory({('aws_vpc','vpc-canary'),('aws_s3_bucket','cg-test')})
        self.assertEqual([x['owned'] for x in rows],[True,False,True]);self.assertNotIn('list_buckets',[x[0] for x in sdk.calls])

class NativeTests(Fakes,unittest.TestCase):
    def test_remote_backend_source_and_exact_account_pin_with_no_real_process(self):
        def process(args,**kw):
            value={'terraform_version':'1.9.8'} if 'version' in args else {'valid':True}
            return types.SimpleNamespace(returncode=0,stdout=json.dumps(value),stderr='')
        with tempfile.TemporaryDirectory() as f:
            folder=Path(f);Native(self.auth,None,process).prepare(folder,generate(configuration(),self.c['support'])[0])
            text=(folder/'main.tf').read_text();self.assertIn('backend "s3" {}',text);self.assertIn('allowed_account_ids = ["111122223333"]',text)
            backend=json.loads((folder/'backend.json').read_text());self.assertTrue(backend['encrypt']);self.assertEqual(backend['dynamodb_table'],self.c['lock_table']);self.assertNotIn('access_key',backend)
            self.assertEqual((folder/'.terraform.lock.hcl').read_bytes(),(ROOT/'terraform/.terraform.lock.hcl').read_bytes())
    def test_plan_exit_two_and_fixed_saved_binary_apply_no_auto_retry(self):
        calls=[]
        plan={'format_version':'1.2','terraform_version':'1.9.8','resource_changes':[]}
        def process(args,**kw):
            calls.append((args,kw));return types.SimpleNamespace(returncode=2 if 'plan' in args else 0,stdout=json.dumps(plan) if 'show' in args else '',stderr='')
        native=Native(self.auth,None,process)
        with tempfile.TemporaryDirectory() as f:
            p=Path(f);self.assertEqual(native.plan(p),plan);native.execute(p)
            self.assertIn('validated.tfplan',calls[-1][0]);self.assertIn('apply',calls[-1][0]);self.assertNotIn('-auto-approve',calls[-1][0]);self.assertEqual(len(calls),3)
            self.assertEqual(calls[-1][1]['env']['AWS_MAX_ATTEMPTS'],'1');self.assertNotIn('CLOUDGUARD_OPERATOR_TOKEN',calls[-1][1]['env'])
    def test_exit_one_does_not_show_plan_or_retry_and_no_apply_without_grant(self):
        calls=[]
        def bad(args,**kw):calls.append(args);return types.SimpleNamespace(returncode=1,stdout='PRIVATE_CANARY',stderr='PRIVATE_CANARY')
        with tempfile.TemporaryDirectory() as f:
            n=Native(self.auth,None,bad)
            with self.assertRaisesRegex(ValueError,'NATIVE_OPERATION_FAILED'):n.plan(Path(f))
            self.assertEqual(len(calls),1);self.g['allow_deploy']=False
            with self.assertRaises(ValueError):n.execute(Path(f))
            self.assertEqual(len(calls),1)
    def test_missing_state_requires_explicit_not_found_not_access_denied(self):
        class Missing(Exception):
            def __init__(self,code):self.response={'Error':{'Code':code}}
        class Client:
            code='404'
            def head_object(self,**kw):raise Missing(self.code)
        client=Client();aws=types.SimpleNamespace(client=lambda *a:client)
        with tempfile.TemporaryDirectory() as f:
            n=Native(self.auth,aws,lambda *a,**kw:(_ for _ in ()).throw(AssertionError('process should not run')))
            self.assertIsNone(n.state(Path(f))['lineage']);client.code='403'
            with self.assertRaisesRegex(ValueError,'STATE_OBSERVATION_UNAVAILABLE'):n.state(Path(f))
    def test_scope_rejects_external_resource_import_replace_counts(self):
        p={'format_version':'1.2','terraform_version':'1.9.8','resource_changes':[{'mode':'managed','type':'aws_instance','address':'aws_instance.this','change':{'actions':['delete','create']}}]}
        self.assertEqual(plan_scope(p),{'create':1,'update':0,'delete':1})
        for change in [lambda r:r.update(type='aws_iam_role'),lambda r:r.update(address='aws_instance.other'),lambda r:r['change'].update(importing={'id':'private'}),lambda r:r['change'].update(actions=['read'])]:
            bad=deepcopy(p);change(bad['resource_changes'][0])
            with self.assertRaises(ValueError):plan_scope(bad)

class FakeAWS:
    def __init__(self):self.checked=False;self.block=False
    def verify(self):self.checked=True;return {'kind':'CONNECTION','status':'VERIFIED','reason':'LIVE_IDENTITY_AND_SUPPORT_VERIFIED','checked_at':NOW}
    def fresh(self):return self.checked
    def empty_bucket(self,name):
        if self.block:raise ValueError('BUCKET_VERSIONS_PRESENT')
    def inventory(self,managed):return [{'type':'aws_vpc','id':'PRIVATE_CANARY','owned':True}]
class FakeNative:
    def __init__(self):self.serial=0;self.calls=[];self.fail=False;self.drifts=[];self.deleting=False
    def prepare(self,p,tf):
        self.calls.append('prepare');(p/'main.tf').write_text(render_hcl(tf))
        for name in ('backend.json','.terraform.lock.hcl'): (p/name).write_text('{}')
    def state(self,p):return {'lineage':'test-native','serial':self.serial,'sha256':str(self.serial),'managed':[['aws_vpc','vpc-test']]}
    def plan(self,p,refresh=False):
        plan={'format_version':'1.2','terraform_version':'1.9.8','resource_changes':[{'mode':'managed','type':'aws_s3_bucket' if self.deleting else 'aws_vpc','address':'aws_s3_bucket.this' if self.deleting else 'aws_vpc.this','change':{'actions':['delete'] if self.deleting else ['create'],'before':{'bucket':'cg-test'},'after_unknown':{}}}],'resource_drift':self.drifts}
        (p/'tfplan.json').write_text(json.dumps(plan));(p/'validated.tfplan').write_bytes(b'test-saved-plan');return plan
    def execute(self,p,deleting=False):
        self.calls.append('execute')
        if self.fail:raise ValueError('UNCERTAIN_EXECUTION')
        self.serial+=1
class FakeGates:
    def __init__(self):self.status='PASS'
    def run(self,p,*,native=False):
        assert native;return {k:{'status':self.status,'reason':'REAL_PLAN_POLICY'} for k in ('terraform_validate','checkov','opa','conftest')}

class LiveEngineTests(Fakes,unittest.TestCase):
    def setUp(self):
        super().setUp();self.temp=tempfile.TemporaryDirectory();self.aws=FakeAWS();self.native=FakeNative();self.gates=FakeGates()
        self.e=LiveEngine(self.temp.name,self.auth,lambda:deepcopy(self.b),self.aws,self.native,self.gates,lambda:self.time[0],lambda:'test-source')
    def tearDown(self):self.temp.cleanup()
    def preview(self):self.e.connectivity();return self.e.preview(configuration())
    def execute(self,j,request=None):return self.e.execute(j['id'],j['confirmation'],request or str(uuid.uuid4()))
    def test_unverified_mode_cannot_plan_no_process_called(self):
        self.assertEqual(self.e.mode,'LIVE_UNVERIFIED')
        with self.assertRaises(ValueError):self.e.preview(configuration())
        self.assertEqual(self.native.calls,[])
    def test_real_engine_plan_single_operator_execute_public_privacy_and_replay(self):
        j=self.preview();self.assertTrue(j['can_deploy']);valid_response({'mode':self.e.mode,'ok':True,'data':j})
        req=str(uuid.uuid4());self.assertEqual(self.execute(j,req)['status'],'SUCCEEDED');self.assertEqual(self.execute(j,req)['status'],'SUCCEEDED')
        self.assertEqual(self.native.calls.count('execute'),1)
        with self.assertRaises(ValueError):self.execute(j)
        s=self.e.status();valid_response({'mode':self.e.mode,'ok':True,'data':s});self.assertNotIn('PRIVATE_CANARY',str(s))
    def test_each_mandatory_gate_unknown_fail_blocks(self):
        for status in ('UNKNOWN','FAIL','NOT_RUN'):
            self.gates.status=status;j=self.preview();self.assertFalse(j['can_deploy'])
            with self.assertRaises(ValueError):self.execute(j)
        self.assertNotIn('execute',self.native.calls)
    def test_state_changes_expiry_revoke_artifact_or_price_change_block(self):
        for change in ('state','expiry','revoke','artifact','price'):
            j=self.preview();p=Path(self.temp.name)/j['id']
            if change=='state':self.native.serial+=1
            if change=='expiry':self.time[0]+=601
            if change=='revoke':self.g['allow_deploy']=False
            if change=='artifact':(p/'validated.tfplan').write_text('tampered')
            if change=='price':self.b['rates']['kms_key_month']['usd_per_unit']='2.00'
            with self.subTest(change=change),self.assertRaises(ValueError):self.execute(j)
            self.time[0]=NOW;self.g['allow_deploy']=True;self.b=book()
        self.assertNotIn('execute',self.native.calls)
    def test_concurrent_operator_deliveries_execute_only_once(self):
        from concurrent.futures import ThreadPoolExecutor
        j=self.preview()
        def action(i):
            try:return self.execute(j)['status']
            except ValueError:return 'DENIED'
        with ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(action,range(3)))
        self.assertEqual(results.count('SUCCEEDED'),1);self.assertEqual(results.count('DENIED'),2);self.assertEqual(self.native.calls.count('execute'),1)
    def test_live_worker_is_frozen_and_unreachable_from_workflows(self):
        from cloudguard import ci_security as c
        import tempfile
        names=[n for k,n in c.FILES.items() if k.startswith('phase6_live_')]
        self.assertIn('backend/cloudguard_live/native.py',names)
        self.assertTrue({p.relative_to(ROOT).as_posix() for p in (ROOT/'backend/cloudguard_live').glob('*.py')}<=set(names),'Every live authorization/worker module must be frozen')
        for workflow in (ROOT/'.github/workflows').glob('*.yml'):
            text=workflow.read_text();self.assertNotIn('serve_platform',text);self.assertNotIn('cloudguard_live',text)
        # Mutating live worker code is rejected by the same closed CI review contract.
        with tempfile.TemporaryDirectory() as f:
            root=Path(f)
            for name in c.FILES.values():
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            target=root/'backend/cloudguard_live/native.py';target.write_text(target.read_text()+'\n# unreviewed change\n')
            self.assertIn('PHASE6_LIVE_NATIVE_CONTRACT_CHANGED',c.verify(root)['errors'])
    def test_failure_is_consumed_recovery_requires_new_plan(self):
        j=self.preview();self.native.fail=True;r=self.execute(j);self.assertEqual(r['status'],'RECOVERY_REQUIRED')
        with self.assertRaises(ValueError):self.execute(j)
        self.native.fail=False
        with self.assertRaises(ValueError):self.e.recover(j['id'])
        self.g['expires_at']-=1;new=self.e.recover(j['id']);self.assertNotEqual(j['id'],new['id'])
    def test_failed_execution_invalidates_other_saved_plans_and_inventory_is_unknown(self):
        first=self.preview();other=self.preview();self.native.fail=True;self.execute(first)
        with self.assertRaises(ValueError):self.execute(other)
        self.assertEqual(self.e.status()['inventory'][0]['status'],'UNKNOWN')
        with self.assertRaises(ValueError):self.e.preview(configuration())
    def test_unmanaged_or_unavailable_inventory_blocks_live_plan(self):
        self.aws.inventory=lambda managed:[{'type':'aws_instance','id':'untracked','owned':False}]
        self.assertEqual(self.preview()['context_reason'],'UNMANAGED_RESOURCES')
        def fail(managed):raise ValueError('PRIVATE_CANARY')
        self.aws.inventory=fail;self.assertEqual(self.preview()['context_reason'],'OBSERVATION_UNKNOWN')
    def test_fresh_drift_uses_real_plan_and_unknown_remains_unknown(self):
        self.execute(self.preview());self.native.drifts=[{'type':'aws_vpc','address':'aws_vpc.this','change':{'after':{'private':'PRIVATE_CANARY'},'after_unknown':{'cidr':True}}}]
        r=self.e.drift();self.assertEqual(r['status'],'UNKNOWN');self.assertNotIn('PRIVATE_CANARY',str(r))
        self.native.drifts[0]['change']['after_unknown']={};r=self.e.drift();self.assertEqual(r['status'],'DRIFTED');valid_response({'mode':self.e.mode,'ok':True,'data':r})
        self.native.drifts=[];self.assertEqual(self.e.drift()['status'],'IN_SYNC')
    def test_actual_drift_blocks_normal_preview_but_allows_reviewed_reconciliation(self):
        self.execute(self.preview());self.native.drifts=[{'type':'aws_vpc','address':'aws_vpc.this','change':{'after':{},'after_unknown':{}}}]
        j=self.e.preview(configuration());self.assertEqual(j['status'],'BLOCKED')
        self.assertTrue(self.e.reconcile()['can_deploy'])
    def test_delete_requires_empty_versions_exact_confirmation_and_delete_grant(self):
        self.execute(self.preview());self.native.deleting=True;self.aws.block=True
        j=self.e.delete_preview();self.assertEqual(j['context_reason'],'DATA_RETENTION_REVIEW');self.assertFalse(j['can_deploy'])
        self.aws.block=False;j=self.e.delete_preview();self.assertTrue(j['can_deploy']);valid_response({'mode':self.e.mode,'ok':True,'data':j})
        with self.assertRaises(ValueError):self.e.execute(j['id'],'',str(uuid.uuid4()))
        self.g['allow_delete']=False
        with self.assertRaises(ValueError):self.execute(j)
        self.g['allow_delete']=True;self.assertEqual(self.execute(j)['status'],'SUCCEEDED')
    def test_live_mode_rejects_simulated_drift_and_wrong_project(self):
        with self.assertRaises(ValueError):self.e.simulate('CHANGE_CONTROL')
        self.e.connectivity();c=configuration();c['project']='other'
        with self.assertRaises(ValueError):self.e.preview(c)
    def test_single_operator_http_dispatch_uses_same_auth_and_csrf(self):
        service=Service(self.e,'x'*32,lambda:NOW)
        session,token=service.dispatch('login',{'token':'x'*32},None,None)
        r,_=service.dispatch('connectivity',{},'cg_phase6='+token,session['csrf']);self.assertEqual(r['status'],'VERIFIED')
        with self.assertRaises(ValueError):service.dispatch('connectivity',{},'cg_phase6='+token,'wrong')

class SecureTemplateTests(unittest.TestCase):
    def test_six_controls_support_real_crr_no_iam_creation_or_exceptions(self):
        tf,r=generate(configuration(),bindings()['support']);bucket=r['aws_s3_bucket.this']['values'];self.assertTrue(bucket['bucket'].startswith('cg-live-sandbox-'))
        self.assertEqual(r['aws_flow_log.this']['values']['log_destination_type'],'s3')
        self.assertTrue(r['aws_s3_bucket_notification.this']['values']['eventbridge'])
        self.assertTrue(r['aws_instance.this']['values']['iam_instance_profile']);self.assertEqual(r['aws_instance.this']['values']['credit_specification'][0]['cpu_credits'],'standard')
        self.assertEqual(r['aws_s3_bucket_replication_configuration.this']['values']['rule'][0]['destination'][0]['encryption_configuration'][0]['replica_kms_key_id'],bindings()['support']['replica_kms_key'])
        self.assertNotIn('checkov:skip',render_hcl(tf));self.assertFalse(any(k.startswith('aws_iam_') for k in r))
    def test_no_ec2_removes_unattached_sg_and_s3_off_has_no_companions(self):
        c=configuration();c['ec2']['enabled']=False;c['s3']['enabled']=False;r=generate(c)[1]
        self.assertNotIn('aws_security_group.this',r);self.assertFalse(any(k.startswith('aws_s3_') for k in r))
if __name__=='__main__':unittest.main()
