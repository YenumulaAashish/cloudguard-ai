"""S3 posture, conservative mapping and previous-phase compatibility."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import data_protection as d
from cloudguard.findings import serialize
from cloudguard.risk import assess_risk,read_document
from cloudguard.integration import schema_validate

ARN='arn:aws:s3:::fixture-example'
TYPES={kind:'aws_s3_bucket_'+suffix for suffix,kind in d.KINDS.items()}

def secure():
    definitions=[('aws_s3_bucket',{'bucket':'fixture-example','id':'fixture-example','arn':ARN}),
      (TYPES['pab'],{k:True for k in d.PAB}), (TYPES['acl'],{'acl':'private'}),
      (TYPES['encryption'],{'rule':[{'apply_server_side_encryption_by_default':[{'sse_algorithm':'AES256'}]}]}),
      (TYPES['versioning'],{'versioning_configuration':[{'status':'Enabled'}]}),
      (TYPES['logging'],{'target_bucket':'fixture-logs'}),
      (TYPES['lifecycle'],{'rule':[{'status':'Enabled','filter':[{}],'abort_incomplete_multipart_upload':[{'days_after_initiation':7}]}]}),
      (TYPES['policy'],{'policy':{'Statement':[{'Effect':'Deny','Principal':'*','Action':'s3:*','Resource':[ARN,ARN+'/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}]}})]
    resources=[{'address':typ+'.example','type':typ,'values':{'bucket':'fixture-example',**values}} for typ,values in definitions]
    return {'format_version':'1.2','planned_values':{'root_module':{'resources':resources}}}

def resources(p):return p['planned_values']['root_module']['resources']
def row(p,c):return next(r for r in resources(p) if r['type']==TYPES.get(c,c))
def remove(p,c):resources(p).remove(row(p,c))
def ids(p):return [r['control_id'] for r in d.analyze(p)['findings']]
def state(p,c):return next(x['state'] for x in d.analyze(p)['checks'] if x['category']==c)
def stmt(**kw):return {'Effect':'Allow','Principal':'*','Action':'s3:GetObject','Resource':ARN+'/*',**kw}
def policy(p,s):row(p,'policy')['values']['policy']={'Statement':s if isinstance(s,list) else [s]}
def mask(p,c,m):
    r=row(p,c);p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'actions':['update'],'after':r['values'],'after_unknown':m}}]


class DataTests(unittest.TestCase):
    def test_secure_and_fixtures(self):
        self.assertEqual(ids(secure()),[])
        for name in ['s3-secure','s3-public']:
            result=d.analyze(read_document(ROOT/'tests/fixtures/data'/f'{name}.json'));d.validate(result)
            self.assertEqual(bool(result['findings']),name=='s3-public')

    def test_empty_and_non_s3(self):
        p=secure();p['planned_values']['root_module']['resources']=[];self.assertEqual(ids(p),[])
        resources(p).append({'address':'aws_vpc.x','type':'aws_vpc','values':{}});self.assertEqual(ids(p),[])

    def test_basic_bucket_has_missing_not_public_claim(self):
        p=secure();p['planned_values']['root_module']['resources']=resources(p)[:1]
        r=d.analyze(p);self.assertTrue(all(c['state']=='MISSING' for c in r['checks']))
        self.assertNotIn('CGA_DATA_005',ids(p));self.assertNotIn('CGA_DATA_003',ids(p))

    def test_pab_multiple_false_one_finding(self):
        p=secure();row(p,'pab')['values'].update({k:False for k in d.PAB})
        self.assertEqual(ids(p),['CGA_DATA_001'])

    def test_acl_custom_grants_unknown(self):
        p=secure();row(p,'acl')['values']['access_control_policy']=[{'grant':[]}]
        self.assertEqual(state(p,'acl'),'UNKNOWN')

    def test_public_policy_and_deny(self):
        for effect,expected in [('Allow',True),('Deny',False)]:
            p=secure();policy(p,stmt(Effect=effect))
            self.assertEqual('CGA_DATA_005' in ids(p),expected)

    def test_conditioned_public_is_unknown(self):
        p=secure();policy(p,stmt(Condition={'StringEquals':{'aws:PrincipalOrgID':'o-example'}}))
        self.assertEqual(state(p,'policy'),'UNKNOWN');self.assertNotIn('CGA_DATA_005',ids(p))

    def test_scoped_principal(self):
        p=secure();policy(p,stmt(Principal={'AWS':'arn:aws:iam::000000000000:role/example'}))
        self.assertNotIn('CGA_DATA_005',ids(p))

    def test_public_aws_principal_list(self):
        p=secure();policy(p,stmt(Principal={'AWS':['*','arn:example']}))
        self.assertIn('CGA_DATA_005',ids(p))

    def test_action_resource_scope(self):
        for changes in [{'Action':'ec2:DescribeVpcs'},{'Resource':'arn:aws:s3:::other/*'},{'Resource':ARN},{'Action':'s3:ListBucket','Resource':ARN+'/*'}]:
            p=secure();policy(p,stmt(**changes));self.assertNotIn('CGA_DATA_005',ids(p));self.assertEqual(state(p,'policy'),'UNKNOWN')

    def test_supported_listbucket(self):
        p=secure();policy(p,stmt(Action='s3:ListBucket',Resource=ARN));self.assertIn('CGA_DATA_005',ids(p))

    def test_policy_duplicate_and_order(self):
        p=secure();policy(p,[stmt(),stmt()]);first=serialize(d.analyze(p))
        self.assertEqual(ids(p).count('CGA_DATA_005'),1)
        row(p,'policy')['values']['policy']['Statement'].reverse();self.assertEqual(first,serialize(d.analyze(p)))
        p=secure();policy(p,[stmt(),stmt(Effect='Deny')]);first=serialize(d.analyze(p))
        row(p,'policy')['values']['policy']['Statement'].reverse();self.assertEqual(first,serialize(d.analyze(p)))

    def test_policy_string_object(self):
        p=secure();first=serialize(d.analyze(p));r=row(p,'policy')['values'];r['policy']=json.dumps(r['policy'])
        self.assertEqual(first,serialize(d.analyze(p)))
        r['policy']={'Statement':secure()['planned_values']['root_module']['resources'][-1]['values']['policy']['Statement'][0]}
        self.assertEqual(first,serialize(d.analyze(p)))

    def test_policy_malformed(self):
        for value in ['{',[],1,'{"Statement":[],"Statement":[]}']:
            p=secure();row(p,'policy')['values']['policy']=value
            with self.assertRaises((ValueError,TypeError)):d.analyze(p)

    def test_missing_statement_unknown(self):
        p=secure();row(p,'policy')['values']['policy']={};self.assertEqual(state(p,'policy'),'UNKNOWN')

    def test_transport_bool_false(self):
        for false in [False,'false']:
            p=secure();row(p,'policy')['values']['policy']['Statement'][0]['Condition']['Bool']['aws:SecureTransport']=false
            self.assertEqual(state(p,'transport'),'ESTABLISHED')

    def test_transport_extra_condition_is_not_proof(self):
        p=secure();s=row(p,'policy')['values']['policy']['Statement'][0];s['Condition']['StringEquals']={'aws:SourceVpce':'vpce-example'}
        self.assertNotEqual(state(p,'transport'),'ESTABLISHED')

    def test_transport_requires_full_scope(self):
        for field,value in [('Resource',ARN),('Action','s3:GetObject'),('Principal',{'AWS':'arn:example'})]:
            p=secure();row(p,'policy')['values']['policy']['Statement'][0][field]=value
            self.assertNotEqual(state(p,'transport'),'ESTABLISHED')

    def test_kms_records_mode_only(self):
        p=secure();row(p,'encryption')['values']['rule'][0]['apply_server_side_encryption_by_default'][0]['sse_algorithm']='aws:kms'
        r=d.analyze(p);self.assertEqual(next(c for c in r['checks'] if c['category']=='encryption')['encryption_mode'],'aws:kms')
        self.assertEqual(r['findings'],[])

    def test_encryption_malformed(self):
        for value in [[],{},[1],[{},{}]]:
            p=secure();row(p,'encryption')['values']['rule']=value
            with self.assertRaises(ValueError):d.analyze(p)

    def test_encryption_unknown_algorithm(self):
        p=secure();row(p,'encryption')['values']['rule'][0]['apply_server_side_encryption_by_default'][0]['sse_algorithm']='unsupported'
        self.assertEqual(state(p,'encryption'),'UNKNOWN')

    def test_lifecycle_disabled_scoped_and_no_abort(self):
        for patching in [{'status':'Disabled'},{'filter':[{'prefix':'only/'}]},{'abort_incomplete_multipart_upload':[]}]:
            p=secure();row(p,'lifecycle')['values']['rule'][0].update(patching)
            self.assertEqual(state(p,'lifecycle'),'WEAK')

    def test_lifecycle_empty_and_other_retention(self):
        for rules in [[],[{'status':'Enabled','expiration':[{'days':30}]}],[{'status':'Enabled','transition':[{'days':30,'storage_class':'GLACIER'}]}]]:
            p=secure();row(p,'lifecycle')['values']['rule']=rules;self.assertEqual(state(p,'lifecycle'),'WEAK')

    def test_missing_vs_unknown_reference(self):
        p=secure();remove(p,'pab');self.assertEqual(state(p,'pab'),'MISSING')
        p=secure();row(p,'pab')['values']['bucket']=None;self.assertEqual(state(p,'pab'),'UNKNOWN')
        self.assertNotIn('CGA_DATA_002',ids(p))

    def test_unknown_bucket(self):
        p=secure();mask(p,'aws_s3_bucket',{'bucket':True,'id':True})
        self.assertTrue(all(c['state']=='UNKNOWN' for c in d.analyze(p)['checks']))

    def test_unmatched_reference(self):
        p=secure();row(p,'pab')['values']['bucket']='unmatched'
        self.assertEqual(state(p,'pab'),'UNKNOWN')

    def test_duplicate_companion_rejected(self):
        p=secure();r=deepcopy(row(p,'pab'));r['address']='aws_s3_bucket_public_access_block.duplicate';resources(p).append(r)
        with self.assertRaises(ValueError):d.analyze(p)

    def test_delete_bucket_and_companion(self):
        p=secure();r=row(p,'aws_s3_bucket');p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':None,'actions':['delete']}}]
        result=d.analyze(p);self.assertEqual(result['checks'],[])
        p=secure();r=row(p,'logging');p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':None,'actions':['delete']}}]
        self.assertEqual(state(p,'logging'),'MISSING')

    def test_replacements_once(self):
        for c in ['aws_s3_bucket','pab']:
            p=secure();r=row(p,c);p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':r['values'],'actions':['delete','create']}}]
            self.assertEqual(ids(p),[]);self.assertEqual(len(d.analyze(p)['checks']),8)

    def test_known_false_and_unknown_pab(self):
        p=secure();row(p,'pab')['values']['block_public_acls']=False
        mask(p,'pab',{'ignore_public_acls':True});self.assertEqual(state(p,'pab'),'UNKNOWN')

    def test_unknown_logging_target(self):
        p=secure();mask(p,'logging',{'target_bucket':True});self.assertEqual(state(p,'logging'),'UNKNOWN')

    def test_unsupported_and_inline(self):
        p=secure();resources(p).append({'address':'aws_s3_bucket_object_lock_configuration.x','type':'aws_s3_bucket_object_lock_configuration','values':{}})
        self.assertIn('CGA_DATA_011',ids(p))
        p=secure();row(p,'aws_s3_bucket')['values']['acl']='private';self.assertTrue(all(c['state']=='UNKNOWN' for c in d.analyze(p)['checks']))

    def test_order_bytes_and_source_immutability(self):
        p=secure();old=deepcopy(p);first=serialize(d.analyze(p));self.assertEqual(p,old)
        resources(p).reverse();self.assertEqual(first,serialize(d.analyze(p)))

    def test_schema_tampering(self):
        original=d.analyze(secure());d.validate(original)
        for patching in [{'extra':True},{'schema_version':'2'}]:
            with self.assertRaises(Exception):d.validate({**original,**patching})
        p=secure();remove(p,'pab');original=d.analyze(p)
        for key,value in [('severity','INVALID'),('control_id','BAD'),('message','changed')]:
            r=deepcopy(original);r['findings'][0][key]=value
            with self.assertRaises(Exception):d.validate(r)

    def test_bounds(self):
        p=secure();row(p,'policy')['values']['policy']=' '*262145
        with self.assertRaises(ValueError):d.analyze(p)
        p=secure();policy(p,[stmt()]*257)
        with self.assertRaises(ValueError):d.analyze(p)
        p=secure();policy(p,stmt(Action=['s3:GetObject']*129))
        with self.assertRaises(ValueError):d.analyze(p)
        p=secure();row(p,'lifecycle')['values']['rule']*=257
        with self.assertRaises(ValueError):d.analyze(p)
        p=secure();resources(p).clear()
        for i in range(257):resources(p).append({'address':f'aws_s3_bucket.b{i}','type':'aws_s3_bucket','values':{'bucket':f'b{i}'}})
        with self.assertRaises(ValueError):d.analyze(p)

    def test_no_network_execution_and_inert_strings(self):
        for text in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake report -->','`rm -rf /`','AKIAEXAMPLEFAKEKEY']:
            p=secure();r=row(p,'aws_s3_bucket');r['address']=text;r['values']['bucket']=text
            policy(p,stmt(Sid=text));original=deepcopy(p)
            with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execute')),patch.dict('os.environ',{},clear=True):
                out=d.analyze(p)
            self.assertEqual(p,original);self.assertTrue(all(text not in r['message'] for r in out['findings']))

    def test_adapter(self):
        for p in [secure(),None]:
            if p is None:p=secure();row(p,'pab')['values']['bucket']=None
            report=d.normalized(d.analyze(p));schema_validate(report,'normalized');assess_risk(report)
            self.assertTrue(all(not f['exception'] and f['file'] is None for f in report['findings']))

    def test_cli_private_no_overwrite_errors(self):
        spec=importlib.util.spec_from_file_location('data_cli',ROOT/'scripts/analyze-data-protection.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'input.json';source.write_text(serialize(secure()))
            with patch.object(cli,'PRIVATE',root/'private'):
                target=root/'private/out.json';args=['--plan',str(source),'--output',str(target)]
                self.assertEqual(cli.main(args),0);before=target.read_bytes()
                self.assertEqual(cli.main(args),2);self.assertEqual(target.read_bytes(),before)
                self.assertEqual(cli.main(['--plan',str(source),'--output',str(root/'public.json')]),2)
                source.write_text('{invalid');self.assertEqual(cli.main(['--plan',str(source),'--output',str(root/'private/new.json')]),2)


    def test_acl_exact_controls_and_severity(self):
        for acl,control,severity in [('public-read','CGA_DATA_003','MEDIUM'),('public-read-write','CGA_DATA_004','CRITICAL')]:
            p=secure();row(p,'acl')['values']['acl']=acl
            result=d.analyze(p)['findings'];self.assertEqual([(r['control_id'],r['severity']) for r in result],[(control,severity)])

    def test_malformed_pab_boolean(self):
        p=secure();row(p,'pab')['values']['block_public_acls']='false'
        with self.assertRaises(ValueError):d.analyze(p)

    def test_duplicate_bucket_identity(self):
        p=secure();r=deepcopy(row(p,'aws_s3_bucket'));r['address']='aws_s3_bucket.duplicate';resources(p).append(r)
        with self.assertRaises(ValueError):d.analyze(p)

    def test_bucket_id_alias(self):
        p=secure();row(p,'aws_s3_bucket')['values']['id']='alias-known';row(p,'pab')['values']['bucket']='alias-known'
        self.assertEqual(ids(p),[])

    def test_nested_modules_and_unknown_create(self):
        p=secure();root=p['planned_values']['root_module'];root['child_modules']=[{'resources':root.pop('resources')}]
        self.assertEqual(ids(p),[])
        p={'format_version':'1.2','planned_values':{'root_module':{}},'resource_changes':[{'address':'aws_s3_bucket.x','type':'aws_s3_bucket','change':{'actions':['create'],'after':None,'after_unknown':True}}]}
        self.assertTrue(all(x['state']=='UNKNOWN' for x in d.analyze(p)['checks']))

    def test_malformed_plan(self):
        for p in [{},{'format_version':'9'}, {**secure(),'errored':True}]:
            with self.assertRaises(ValueError):d.analyze(p)

    def test_output_minimization(self):
        p=secure();row(p,'logging')['values']['target_bucket']='PRIVATE_LOG_TARGET'
        row(p,'encryption')['values']['rule'][0]['apply_server_side_encryption_by_default'][0]['kms_master_key_id']='PRIVATE_KEY_IDENTIFIER'
        row(p,'policy')['values']['policy']['Statement'][0]['Sid']='PRIVATE_API_KEY_TOKEN'
        text=serialize(d.analyze(p))
        for sentinel in ['PRIVATE_LOG_TARGET','PRIVATE_KEY_IDENTIFIER','PRIVATE_API_KEY_TOKEN',ARN]:self.assertNotIn(sentinel,text)
        self.assertLess(len(text.encode()),262144)

    def test_nonaws_principal_is_review_context(self):
        p=secure();policy(p,stmt(Principal={'Service':'example.amazonaws.com'}))
        self.assertEqual(state(p,'policy'),'UNKNOWN');self.assertNotIn('CGA_DATA_005',ids(p))


    def test_provider_shaped_empty_lifecycle_filter(self):
        p=secure();rule=row(p,'lifecycle')['values']['rule'][0]
        rule['prefix']=None
        rule['filter']=[{'prefix':None,'and':[],'tag':[],'object_size_greater_than':None,'object_size_less_than':None}]
        self.assertEqual(state(p,'lifecycle'),'ESTABLISHED')
        rule['filter'][0]['object_size_greater_than']=0
        self.assertEqual(state(p,'lifecycle'),'WEAK')


def add(name,mutate,category,expected):
    def case(self):
        p=secure();mutate(p);self.assertEqual(state(p,category),expected)
    setattr(DataTests,'test_'+name,case)
for field in d.PAB:add('pab_false_'+field,lambda p,f=field:row(p,'pab')['values'].update({f:False}),'pab','WEAK')
for c in d.CATEGORIES:add('missing_'+c,lambda p,c=c:remove(p,'policy' if c=='transport' else c),c,'MISSING')
for c,field in [('pab','block_public_acls'),('acl','acl'),('policy','policy'),('encryption','rule'),('versioning','versioning_configuration'),('logging','target_bucket'),('lifecycle','rule')]:add('unknown_'+c,lambda p,c=c,f=field:mask(p,c,{f:True}),c,'UNKNOWN')
for acl,expected in [('private','REVIEWED'),('public-read','WEAK'),('public-read-write','WEAK'),(None,'UNKNOWN')]:add('acl_'+str(acl),lambda p,v=acl:row(p,'acl')['values'].update(acl=v),'acl',expected)
for status,expected in [('Enabled','ESTABLISHED'),('Suspended','WEAK'),('Disabled','WEAK'),(None,'UNKNOWN')]:add('versioning_'+str(status),lambda p,v=status:row(p,'versioning')['values']['versioning_configuration'][0].update(status=v),'versioning',expected)
for days,expected in [(1,'ESTABLISHED'),(7,'ESTABLISHED'),(8,'WEAK'),(30,'WEAK')]:add('abort_'+str(days),lambda p,v=days:row(p,'lifecycle')['values']['rule'][0]['abort_incomplete_multipart_upload'][0].update(days_after_initiation=v),'lifecycle',expected)
for negate in ['NotPrincipal','NotAction','NotResource']:add('negated_'+negate,lambda p,k=negate:policy(p,stmt(**{k:'*'})),'policy','UNKNOWN')
