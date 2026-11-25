"""Offline Phase 6 FR-4/O4 and exact-plan operator authorization; no cloud calls."""
from copy import deepcopy
from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard.phase6.config import validate,generate,mock_plan,digest,canonical
from cloudguard.phase6.drift import detect
from cloudguard.phase6.cost import estimate
from cloudguard.phase6.engine import Engine
from cloudguard.phase6.gates import MANDATORY
from cloudguard.phase6.http import Service,valid_response
NOW=datetime(2026,11,26,8,tzinfo=timezone.utc).timestamp()
def configuration():return json.loads((ROOT/'tests/fixtures/phase6/configuration.json').read_text())
class PassedFixture:
    def run(self,folder):return {k:{'status':'PASS','reason':'MOCK_TEST_EVIDENCE'} for k in MANDATORY if k!='cost'}

class ConfigurationTests(unittest.TestCase):
    def test_deterministic_closed_templates_and_caller_immutable(self):
        c=configuration();original=deepcopy(c);a=generate(c);self.assertEqual(a,generate(c));self.assertEqual(c,original)
        tf,r=a;self.assertEqual(tf['terraform']['required_version'],'= 1.9.8')
        self.assertFalse(any('iam' in name for name in r));self.assertEqual(tf['provider']['aws']['region'],'ap-south-1')
        instance=r['aws_instance.this']['values'];self.assertFalse(instance['associate_public_ip_address'])
        self.assertEqual(instance['metadata_options'][0]['http_tokens'],'required');self.assertTrue(instance['root_block_device'][0]['encrypted'])
        self.assertFalse(r['aws_s3_bucket.this']['values']['force_destroy'])
    def test_invalid_injection_types_quotas_and_unapproved_identifiers(self):
        for mutate in [lambda c:c.update(extra='ignored'),lambda c:c.update(project='${file("secret")}'),lambda c:c.update(region='us-east-1'),lambda c:c['ec2'].update(ami='arbitrary'),lambda c:c['ec2'].update(instance_type='huge'),lambda c:c['vpc'].update(cidr='0.0.0.0/0'),lambda c:c['vpc'].update(subnet_cidr='192.168.1.0/24'),lambda c:c['ec2'].update(enabled=1),lambda c:c['ec2'].update(hours=True),lambda c:c['s3'].update(storage_gb=101),lambda c:c.update(budget_usd='NaN'),lambda c:c['vpc'].update(enabled=False)]:
            c=configuration();mutate(c)
            with self.subTest(c=c),self.assertRaises(Exception):validate(c)
    def test_budget_or_usage_edit_does_not_rename_bucket(self):
        c=configuration();before=generate(c)[1]['aws_s3_bucket.this'];c['budget_usd']='8.00';c['ec2']['hours']=48
        self.assertEqual(before,generate(c)[1]['aws_s3_bucket.this'])
    def test_mock_preview_marks_replacement_as_deletion_and_creation(self):
        c=configuration();old=generate(c)[1];c['vpc']['cidr']='10.40.0.0/17';new=generate(c)[1]
        plan=mock_plan(new,old);row=next(r for r in plan['resource_changes'] if r['type']=='aws_vpc')
        self.assertEqual(row['change']['actions'],['delete','create']);self.assertTrue(plan['mock_only'])

class DriftTests(unittest.TestCase):
    def setUp(self):
        self.declared=generate(configuration())[1];self.snapshot={'complete':True,'lineage':'fixture','serial':1,'captured_at':NOW,'resources':{a:deepcopy(r)|{'owned':True} for a,r in self.declared.items()}}
    def detect(self):return detect(self.declared,self.snapshot,'fixture',1,NOW)
    def test_same_declared_actual_mock_and_computed_identity(self):
        before=deepcopy(self.snapshot);self.assertEqual(self.detect()['status'],'IN_SYNC');self.assertEqual(self.snapshot,before)
        self.snapshot['resources']['aws_vpc.this']['values']['id']='mock-computed';self.assertEqual(self.detect()['status'],'IN_SYNC')
    def test_changed_security_rule_and_no_value_leak(self):
        self.snapshot['resources']['aws_security_group.this']['values']['ingress']=[{'private':'PRIVATE_CANARY'}]
        r=self.detect();self.assertEqual(r['status'],'DRIFTED');self.assertEqual(r['changes'][0]['fields'],['NETWORK_RULES']);self.assertNotIn('PRIVATE_CANARY',canonical(r))
    def test_missing_managed_resource_is_distinct(self):
        self.snapshot['resources'].pop('aws_instance.this');self.assertEqual(self.detect()['changes'][0]['kind'],'MISSING')
    def test_unmanaged_resource_never_silently_deleted(self):
        self.snapshot['resources']['aws_instance.other']={'type':'aws_instance','values':{},'owned':False}
        self.assertEqual(self.detect()['changes'][0]['kind'],'UNMANAGED')
    def test_unavailable_stale_incomplete_or_wrong_state_is_unknown(self):
        for key,value in [('complete',False),('lineage','other'),('serial',2),('serial',True),('captured_at',NOW-301),('captured_at',NOW+1),('resources',None)]:
            old=deepcopy(self.snapshot);self.snapshot[key]=value
            with self.subTest(key=key):self.assertEqual(self.detect()['status'],'UNKNOWN')
            self.snapshot=old
    def test_unresolved_unowned_or_unsupported_context_is_unknown(self):
        for key,value in [('unresolved',True),('owned',False),('type','unsupported')]:
            old=deepcopy(self.snapshot);self.snapshot['resources']['aws_instance.this'][key]=value
            with self.subTest(key=key):self.assertEqual(self.detect()['status'],'UNKNOWN')
            self.snapshot=old
        self.snapshot['resources']['aws_instance.this']['values']['unrecognized_security_field']=True
        self.assertEqual(self.detect()['status'],'UNKNOWN')
    def test_invalid_unmanaged_record_is_unknown(self):
        self.snapshot['resources']['malformed']=None;self.assertEqual(self.detect()['status'],'UNKNOWN')

class CostTests(unittest.TestCase):
    def setUp(self):self.catalog=json.loads((ROOT/'security/phase6-mock-prices.json').read_text())
    def test_decimal_estimate_budget_and_explicit_mock_basis(self):
        r=estimate(configuration(),self.catalog,'20.00',NOW);self.assertEqual(r['status'],'PASS');self.assertEqual(r['estimate_usd'],'4.62');self.assertEqual(r['mode'],'MOCK_ONLY')
        self.assertEqual(estimate(configuration(),self.catalog,'1.00',NOW)['status'],'FAIL')
    def test_missing_stale_negative_or_invalid_prices_never_zero(self):
        for mutate in [lambda p:p['unit_prices'].pop('t3.micro'),lambda p:p.update(expires_at='2026-11-25T00:00:00Z'),lambda p:p['unit_prices'].update(t3_micro='NaN'),lambda p:p['unit_prices'].update(t3_micro='-1')]:
            p=deepcopy(self.catalog);mutate(p);r=estimate(configuration(),p,'20.00',NOW);self.assertEqual(r['status'],'UNKNOWN');self.assertIsNone(r['estimate_usd'])

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.folder=Path(self.tmp.name)
        self.time=[NOW];self.source=['fixture-source'];self.prices=self.folder/'prices.json';self.prices.write_bytes((ROOT/'security/phase6-mock-prices.json').read_bytes())
        self.engine=Engine(self.folder/'private',runner=PassedFixture(),clock=lambda:self.time[0],source=lambda:self.source[0],prices=self.prices)
    def preview(self):return self.engine.preview(configuration())
    def execute(self,j):return self.engine.execute(j['id'],j['confirmation'],str(uuid.uuid4()))
    def deploy(self):j=self.preview();self.execute(j);return j
    def mutate(self,fn):
        with self.engine.store.transaction() as (db,s):fn(s);s['observed_revision']+=1;self.engine.store.save(db,s,'TEST_OBSERVATION')
    def test_single_operator_action_executes_exact_mock_plan_and_inventory(self):
        j=self.preview();self.assertTrue(j['can_deploy']);valid_response({'ok':True,'mode':'MOCK_ONLY','data':j})
        with patch('socket.socket',side_effect=AssertionError('network')):result=self.execute(j)
        self.assertEqual(result['status'],'MOCK_SUCCEEDED');s=self.engine.status();self.assertEqual(s['state_serial'],1);self.assertTrue(s['inventory']);self.assertFalse(s['busy'])
        valid_response({'ok':True,'mode':'MOCK_ONLY','data':s})
        self.assertEqual(self.engine.drift()['status'],'IN_SYNC')
    def test_replay_denied_and_same_request_is_idempotent(self):
        j=self.preview();req=str(uuid.uuid4());self.engine.execute(j['id'],'',req);self.engine.execute(j['id'],'',req)
        self.assertEqual(self.engine.status()['state_serial'],1)
        with self.assertRaises(ValueError):self.execute(j)
    def test_each_missing_unknown_or_failed_gate_blocks_deploy(self):
        for name in ('terraform_validate','checkov','opa','conftest'):
            for status in ('FAIL','UNKNOWN','NOT_RUN'):
                class Failed:
                    def run(_,folder):r=PassedFixture().run(folder);r[name]['status']=status;return r
                self.engine.runner=Failed();j=self.preview();self.assertFalse(j['can_deploy'])
                with self.assertRaises(ValueError):self.execute(j)
    def test_budget_limit_blocks_even_when_tools_pass(self):
        self.engine.cap='1.00';j=self.preview();self.assertFalse(j['can_deploy']);self.assertEqual(j['gates']['cost']['status'],'FAIL')
    def test_expired_source_price_or_cap_change_requires_new_preview(self):
        j=self.preview();self.time[0]+=601
        with self.assertRaises(ValueError):self.execute(j)
        self.time[0]=NOW;j=self.preview();self.source[0]='changed'
        with self.assertRaises(ValueError):self.execute(j)
        self.source[0]='fixture-source';j=self.preview();p=json.loads(self.prices.read_text());p['unit_prices']['t3.micro']='0.02';self.prices.write_text(json.dumps(p))
        with self.assertRaises(ValueError):self.execute(j)
        j=self.preview();self.engine.cap='19.00'
        self.assertFalse(self.engine.status()['history'][0]['can_deploy'])
        with self.assertRaises(ValueError):self.execute(j)
    def test_artifact_tamper_after_gates_is_denied(self):
        j=self.preview();(self.engine.store.folder/j['id']/'main.tf').write_text('{}')
        with self.assertRaises(ValueError):self.execute(j)
    def test_gate_input_tamper_is_not_bound_as_validated(self):
        class Bad:
            def run(_,folder):(folder/'main.tf').write_text('{}');return PassedFixture().run(folder)
        self.engine.runner=Bad()
        with self.assertRaisesRegex(ValueError,'GATE_INPUT_CHANGED'):self.preview()
    def test_state_change_invalidates_prior_plan(self):
        self.deploy();j=self.preview();self.engine.simulate('CHANGE_CONTROL')
        with self.assertRaises(ValueError):self.execute(j)
        self.assertFalse(self.engine.status()['history'][0]['can_deploy'])
    def test_drift_alert_dedup_and_explicit_reconciliation(self):
        self.deploy();before=self.engine.status()['state_serial'];r=self.engine.simulate('CHANGE_CONTROL');self.assertEqual(r['status'],'DRIFTED')
        count=len(r['alerts']);self.assertEqual(len(self.engine.drift()['alerts']),count);self.assertEqual(self.engine.status()['state_serial'],before)
        self.assertFalse(self.preview()['can_deploy']);j=self.engine.reconcile();self.assertTrue(j['can_deploy']);self.execute(j)
        r=self.engine.drift();self.assertEqual(r['status'],'IN_SYNC');self.assertTrue(all(a['status']=='RESOLVED' for a in r['alerts']))
    def test_unavailable_observations_do_not_clear_alerts_or_allow_reconciliation(self):
        self.deploy();self.engine.simulate('CHANGE_CONTROL');r=self.engine.simulate('OBSERVATION_UNAVAILABLE');self.assertEqual(r['status'],'UNKNOWN')
        self.assertTrue(any(a['status']=='OPEN' for a in r['alerts']));self.assertFalse(self.engine.reconcile()['can_deploy'])
        self.assertTrue(all(r['status']=='UNKNOWN' for r in self.engine.status()['inventory']))
    def test_deletion_requires_explicit_confirmation_and_cannot_empty_data(self):
        self.deploy();j=self.engine.delete_preview();self.assertTrue(j['confirmation'].startswith('DELETE '))
        with self.assertRaises(ValueError):self.engine.execute(j['id'],'',str(uuid.uuid4()))
        self.execute(j);self.assertEqual(self.engine.status()['inventory'],[])
        self.deploy();self.mutate(lambda s:s['observed']['aws_s3_bucket.this'].update(objects=1))
        self.assertFalse(self.engine.delete_preview()['can_deploy'])
        c=configuration();c['s3']['enabled']=False;self.assertFalse(self.engine.preview(c)['can_deploy'])
    def test_partial_fault_never_success_and_recovery_is_fresh_gated_plan(self):
        self.engine.fault_after=1;j=self.preview();r=self.execute(j);self.assertEqual(r['status'],'RECOVERY_REQUIRED');self.assertEqual(self.engine.status()['state_serial'],0)
        self.engine.fault_after=None;recovery=self.engine.recover(j['id']);self.assertNotEqual(recovery['id'],j['id']);self.assertTrue(recovery['can_deploy']);self.execute(recovery)
        self.assertEqual(self.engine.drift()['status'],'IN_SYNC')
    def test_no_recovery_until_explicit_expired_lease_acknowledgment(self):
        j=self.preview()
        with self.engine.store.transaction() as (db,s):
            db.execute("UPDATE jobs SET status='EXECUTING' WHERE id=?",(j['id'],));s['active_job']={'id':j['id'],'lease_until':NOW+30};self.engine.store.save(db,s,'TEST_INTERRUPTED_JOB',j['id'])
        with self.assertRaises(ValueError):self.engine.recover(j['id'])
        self.time[0]+=31;self.assertTrue(self.engine.recover(j['id'])['can_deploy'])
    def test_concurrent_exact_plans_cannot_both_mutate_state(self):
        a=self.preview();b=self.preview()
        def run(j):
            try:self.execute(j);return True
            except Exception:return False
        with ThreadPoolExecutor(max_workers=2) as p:results=list(p.map(run,[a,b]))
        self.assertEqual(sum(results),1);self.assertEqual(self.engine.status()['state_serial'],1)
    def test_private_observation_values_not_in_drift_inventory_or_audit(self):
        self.deploy();self.mutate(lambda s:s['observed']['aws_s3_bucket.this']['values'].update(tags={'secret':'PRIVATE_CANARY'}))
        self.assertNotIn('PRIVATE_CANARY',canonical(self.engine.drift()));self.assertNotIn('PRIVATE_CANARY',canonical(self.engine.status()))
    def test_unmanaged_resource_cannot_be_deleted_or_reconciled(self):
        self.deploy();self.mutate(lambda s:s['observed'].update({'aws_instance.PRIVATE_CANARY':{'type':'aws_instance','values':{},'owned':False}}))
        r=self.engine.drift();self.assertEqual(r['status'],'DRIFTED');self.assertNotIn('PRIVATE_CANARY',canonical(r));self.assertFalse(self.engine.reconcile()['can_deploy']);self.assertFalse(self.engine.delete_preview()['can_deploy'])
    def test_state_job_and_audit_tampering_detected(self):
        self.preview()
        with closing(sqlite3.connect(self.engine.store.path)) as db:db.execute("UPDATE state SET payload='{}'");db.commit()
        with self.assertRaises(ValueError):self.engine.status()
    def test_sealed_plan_cannot_be_replaced_even_with_recomputed_row_hash(self):
        j=self.preview()
        with closing(sqlite3.connect(self.engine.store.path)) as db:
            payload=json.loads(db.execute('SELECT payload FROM jobs WHERE id=?',(j['id'],)).fetchone()[0]);payload['config']['budget_usd']='999.00'
            db.execute('UPDATE jobs SET payload=?,seal=? WHERE id=?',(canonical(payload),digest(payload),j['id']));db.commit()
        with self.assertRaises(ValueError):self.engine.status()

class SessionTests(unittest.TestCase):
    def setUp(self):self.clock=[NOW];self.service=Service(None,'synthetic-operator-secret-for-mock-tests',lambda:self.clock[0])
    def login(self):return self.service.login({'token':'synthetic-operator-secret-for-mock-tests'})
    def test_session_expiry_csrf_and_logout(self):
        data,token=self.login();cookie='cg_phase6='+token
        self.service.authorized(cookie,data['csrf'])
        with self.assertRaises(ValueError):self.service.authorized(cookie,'wrong')
        self.clock[0]+=901
        with self.assertRaises(ValueError):self.service.authorized(cookie,data['csrf'])
    def test_missing_session_secret_bruteforce_and_injection(self):
        with self.assertRaises(ValueError):Service(None,'')
        for _ in range(5):
            with self.assertRaises(ValueError):self.service.login({'token':'wrong'})
        with self.assertRaisesRegex(ValueError,'LOGIN_RATE_LIMITED'):self.login()
        with self.assertRaises(ValueError):self.service.login({'token':'x','actor':'forged'})
    def test_no_reviewer_or_approval_endpoint(self):
        data,token=self.login()
        for action in ('approve','reviewers','approval-dashboard'):
            with self.assertRaises(ValueError):self.service.dispatch(action,{},'cg_phase6='+token,data['csrf'])


class NativeGateContractTests(unittest.TestCase):
    def test_real_runner_strips_credentials_and_keeps_failed_scans_failed(self):
        from cloudguard.phase6 import gates
        from types import SimpleNamespace
        calls=[]
        def run(args,**kw):
            calls.append((args,kw));name=args[0]
            if name=='terraform':value={'valid':True};code=0
            elif name=='checkov':value={'check_type':'terraform','summary':{'passed':1,'failed':1,'skipped':0,'parsing_errors':0},'results':{'failed_checks':[{'check_id':'CKV_AWS_18','resource':'PRIVATE_CANARY'}]}};code=1
            elif name=='opa':value={'result':[{'expressions':[{'value':[]}]}]};code=0
            else:value=[{'successes':13}];code=0
            return SimpleNamespace(returncode=code,stdout=json.dumps(value))
        with tempfile.TemporaryDirectory() as folder,patch.object(gates,'tool',side_effect=lambda n:[n]),patch.object(gates.subprocess,'run',side_effect=run),patch.dict('os.environ',{'AWS_ACCESS_KEY_ID':'PRIVATE_CANARY','OPENAI_API_KEY':'PRIVATE_CANARY','CLOUDGUARD_OPERATOR_TOKEN':'PRIVATE_CANARY'}):
            r=gates.ToolGates().run(Path(folder));self.assertEqual(r['checkov']['status'],'FAIL');self.assertEqual(r['opa']['status'],'PASS')
            self.assertNotIn('PRIVATE_CANARY',canonical(r))
            for args,kw in calls:
                self.assertNotIn('AWS_ACCESS_KEY_ID',kw['env']);self.assertNotIn('OPENAI_API_KEY',kw['env']);self.assertNotIn('CLOUDGUARD_OPERATOR_TOKEN',kw['env']);self.assertNotIn('plan',args)
    def test_unavailable_tools_never_report_pass(self):
        from cloudguard.phase6 import gates
        with tempfile.TemporaryDirectory() as folder,patch.object(gates,'tool',side_effect=FileNotFoundError):
            self.assertTrue(all(r['status']=='NOT_RUN' for r in gates.ToolGates().run(Path(folder)).values()))
    def test_browser_and_server_public_contract_are_identical(self):
        self.assertEqual(json.loads((ROOT/'security/phase6-public.schema.json').read_text()),json.loads((ROOT/'frontend/src/data/phase6-public.schema.json').read_text()))
