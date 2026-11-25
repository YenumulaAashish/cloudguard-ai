"""Quota, replay, durability and gate tests. Synthetic local grants only; no AWS."""
from copy import deepcopy
from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import authorization as a
spec=importlib.util.spec_from_file_location('planning_auth',ROOT/'scripts/planning-authorization.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
NOW=datetime(2026,11,25,10,tzinfo=timezone.utc).timestamp()

def grant():
    return {'version':1,'id':'CG-PLAN-TEST','approval':'APPROVED','owner':'YenumulaAashish',
      'approved_at':'2026-11-25T00:00:00Z','starts_at':'2026-11-25T00:00:00Z','expires_at':'2026-12-02T00:00:00Z',
      'max_attempts':5,'max_daily':2,'allow_self_review':False,'scope':{'repository':a.REPOSITORY,'repository_id':'1379194368',
      'owner_id':'212769106','ref':'refs/heads/main','workflow':a.WORKFLOW,'subject':a.SUBJECT,
      'audience':'sts.amazonaws.com','region':'ap-south-1','role':'arn:aws:iam::111122223333:role/cloudguard-ai-plan',
      'bucket':'synthetic-sandbox','sha':'a'*40,'source_digest':'b'*64}}

def environment():
    s=grant()['scope']
    return {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1',
       'RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux','GITHUB_RUN_ID':'123','GITHUB_REPOSITORY':s['repository'],
       'GITHUB_REPOSITORY_ID':s['repository_id'],'GITHUB_REPOSITORY_OWNER_ID':s['owner_id'],'GITHUB_REF':s['ref'],
       'GITHUB_WORKFLOW_REF':s['workflow'],'AWS_REGION':s['region'],'PLAN_ROLE':s['role'],
       'TF_VAR_bucket_name':s['bucket'],'GITHUB_SHA':s['sha'],'CLOUDGUARD_SOURCE_DIGEST':s['source_digest'],
       'GITHUB_ACTOR':'dispatcher','AWS_PLAN_ENABLED':'true','AWS_PLAN_REVIEW_APPROVED':'true','GH_TOKEN':'synthetic-token'}

class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'ledger.db';self.ledger=a.Ledger(self.path);self.g=grant()
        self.ledger.initialize(self.g)
    def reserve(self,run='1',now=NOW):return self.ledger.reserve(run,self.g['scope'],now)
    def close(self,run,nonce,now=NOW):self.ledger.transition(run,nonce,'FAILED',now)
    def test_approved_window_and_failed_attempt_are_persistent(self):
        nonce=self.reserve();self.ledger.transition('1',nonce,'STARTED',NOW,self.g['scope']);self.close('1',nonce)
        other=a.Ledger(self.path)
        with self.assertRaises(ValueError):other.reserve('1',self.g['scope'],NOW)
        self.assertTrue(other.reserve('2',self.g['scope'],NOW))
    def test_invalid_approval_limits_scope_and_shape(self):
        variants=[('approval','PROPOSED'),('owner','someone'),('max_attempts',6),('max_daily',3),('max_attempts',True),('max_daily',0),('expires_at','2026-12-02T00:00:01Z'),('starts_at','2026-11-24T00:00:00Z'),('approved_at','2026-11-26T00:00:00Z'),('version',2),('allow_self_review','true'),('extra','secret')]
        for k,v in variants:
            with self.subTest(k=k,v=v),self.assertRaises(Exception):a.validate_grant(dict(self.g,**{k:v}))
        for k in self.g['scope']:
            value=deepcopy(self.g);value['scope'][k]='INVALID_VALUE'
            with self.subTest(scope=k),self.assertRaises(Exception):a.validate_grant(value)
    def test_missing_ledger_and_anchor_never_recreate(self):
        self.path.unlink()
        with self.assertRaises(Exception):self.reserve()
        self.assertFalse(self.path.exists())
    def test_cannot_initialize_over_existing_authority(self):
        with self.assertRaises(Exception):self.ledger.initialize(self.g)
    def test_corrupt_or_missing_anchor_denies(self):
        self.ledger.anchor.write_text('bad')
        with self.assertRaises(Exception):self.reserve()
        self.ledger.anchor.unlink()
        with self.assertRaises(Exception):self.reserve()
    def test_db_only_rollback_denies(self):
        before=self.path.read_bytes();n=self.reserve();self.close('1',n)
        self.path.write_bytes(before)
        with self.assertRaises(Exception):self.reserve('2')
    def test_partial_commit_denies_without_repair(self):
        with patch('cloudguard.authorization.os.replace',side_effect=OSError('crash')):
            with self.assertRaises(Exception):self.reserve()
        with self.assertRaises(Exception):self.reserve('2')
    def test_stale_exclusive_lock_denies_without_deleting_it(self):
        self.ledger.lock.write_text('crash')
        with self.assertRaises(Exception):self.reserve()
        self.assertTrue(self.ledger.lock.exists())
    def test_window_not_yet_started_expired_or_clock_regressed(self):
        for now in (NOW-2*86400,NOW+7*86400):
            with self.assertRaises(Exception):self.reserve(now=now)
        n=self.reserve();self.close('1',n)
        with self.assertRaises(Exception):self.reserve('2',NOW-1)
    def test_wrong_exact_scope_denies(self):
        for key in self.g['scope']:
            s=dict(self.g['scope']);s[key]='other'
            with self.subTest(key=key),self.assertRaises(Exception):self.ledger.reserve('1',s,NOW)
    def test_two_per_utc_day_including_failure_and_cancellation(self):
        n=self.reserve('1');self.close('1',n)
        n=self.reserve('2');self.ledger.transition('2',n,'CANCELLED',NOW)
        with self.assertRaises(Exception):self.reserve('3')
        self.assertTrue(self.reserve('3',NOW+86400))
    def test_five_total_across_days(self):
        for i in range(5):
            when=NOW+(i//2)*86400;n=self.reserve(str(i+1),when);self.close(str(i+1),n,when)
        with self.assertRaises(Exception):self.reserve('6',NOW+3*86400)
    def test_one_inflight_and_cross_connection_concurrency(self):
        def work(i):
            try:a.Ledger(self.path).reserve(str(i),self.g['scope'],NOW);return True
            except Exception:return False
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(work,range(1,9)))
        self.assertEqual(sum(results),1)
    def test_receipt_nonce_and_start_are_single_use(self):
        n=self.reserve()
        with self.assertRaises(Exception):self.ledger.transition('1','wrong','STARTED',NOW,self.g['scope'])
        self.ledger.transition('1',n,'STARTED',NOW,self.g['scope'])
        with self.assertRaises(Exception):self.ledger.transition('1',n,'STARTED',NOW,self.g['scope'])
    def test_expiry_or_revocation_after_reservation_blocks_start(self):
        n=self.reserve();self.ledger.revoke()
        with self.assertRaises(Exception):self.ledger.transition('1',n,'STARTED',NOW,self.g['scope'])
        self.close('1',n)
        with self.assertRaises(Exception):self.reserve('2')
    def test_expiry_after_reservation_blocks_start(self):
        n=self.reserve()
        with self.assertRaises(Exception):self.ledger.transition('1',n,'STARTED',NOW+7*86400,self.g['scope'])
    def test_corrupt_database_denies(self):
        self.path.write_bytes(b'not sqlite')
        with self.assertRaises(Exception):self.reserve()
    def test_environment_manual_main_protected_runner_no_reruns(self):
        env=environment();self.assertEqual(a.context(env),self.g['scope'])
        for k,v in [('GITHUB_EVENT_NAME','pull_request'),('GITHUB_RUN_ATTEMPT','2'),('RUNNER_ENVIRONMENT','github-hosted'),('RUNNER_OS','Windows'),('GITHUB_RUN_ID','../bad')]:
            with self.subTest(k=k),self.assertRaises(Exception):a.context(dict(env,**{k:v}))
    def test_github_protection_and_human_review(self):
        env=environment();branch={'protected':True,'commit':{'sha':env['GITHUB_SHA']}}
        review=[{'state':'approved','user':{'type':'User','login':'reviewer'},'environments':[{'name':'aws-plan'}]}]
        cli.github_evidence(env,get=lambda p:review if p.endswith('/approvals') else branch)
        for bad in [[],[{'state':'rejected','user':{'type':'User','login':'reviewer'},'environments':[{'name':'aws-plan'}]}],[{'state':'approved','user':{'type':'Bot'},'environments':[{'name':'aws-plan'}]}],[{'state':'approved','user':{'type':'User','login':'reviewer'},'environments':[{'name':'other'}]}]]:
            with self.subTest(review=bad),self.assertRaises(Exception):cli.github_evidence(env,get=lambda p:bad if p.endswith('/approvals') else branch)
        for bad in [{'protected':False,'commit':{'sha':env['GITHUB_SHA']}},{'protected':True,'commit':{'sha':'c'*40}}]:
            with self.assertRaises(Exception):cli.github_evidence(env,get=lambda p:review if p.endswith('/approvals') else bad)
    def test_missing_or_failed_or_stale_security_evidence_denies(self):
        env=dict(environment(),CLOUDGUARD_LEDGER_PATH=str(self.path))
        ctx={'source_digest':'b'*64,'started_at':'2026-11-25T10:00:00+00:00'}
        with patch.object(cli,'evidence_context',return_value=ctx),patch.object(cli,'fingerprint',return_value='b'*64),patch.object(cli.time,'time',return_value=NOW),patch.object(cli,'load',return_value={'result':'PASS'}),patch.object(cli,'github_evidence'):
            self.assertEqual(cli.gate(env)[1],self.g['scope'])
            with patch.object(cli,'load',return_value={'result':'FAIL'}),self.assertRaises(Exception):cli.gate(env)
            with patch.object(cli,'load',return_value={}),self.assertRaises(Exception):cli.gate(env)
            with patch.object(cli,'fingerprint',return_value='c'*64),self.assertRaises(Exception):cli.gate(env)
            with patch.object(cli.time,'time',return_value=NOW+1801),self.assertRaises(Exception):cli.gate(env)
            for key in ('AWS_PLAN_ENABLED','AWS_PLAN_REVIEW_APPROVED'):
                with self.assertRaises(Exception):cli.gate(dict(env,**{key:'false'}))
            with self.assertRaises(Exception):cli.gate(dict(env,CLOUDGUARD_LEDGER_PATH=str(ROOT/'ledger.db')))

    def test_cli_lifecycle_and_denial_does_not_print_sensitive_values(self):
        from contextlib import redirect_stdout
        from io import StringIO
        env=environment()
        root=Path(self.tmp.name)/'checkout';root.mkdir()
        with patch.object(cli,'ROOT',root),patch.object(cli,'gate',return_value=(self.ledger,self.g['scope'])),patch.dict('os.environ',dict(env,CLOUDGUARD_LEDGER_PATH=str(self.path),CI_JOB_STATUS='failure'),clear=True),patch.object(cli.time,'time',return_value=NOW):
            for action in ('reserve','start','finish'):
                with patch.object(sys,'argv',['planning-authorization.py',action]):self.assertEqual(cli.main(),0)
            output=StringIO()
            with patch.object(sys,'argv',['planning-authorization.py','start']),redirect_stdout(output):self.assertEqual(cli.main(),1)
            self.assertNotIn('111122223333',output.getvalue());self.assertNotIn('synthetic-token',output.getvalue())
            self.assertNotIn('synthetic-sandbox',output.getvalue())
    def test_rejected_review_cannot_be_overridden_by_older_approval(self):
        env=environment();reviews=[{'state':s,'user':{'type':'User','login':'reviewer'},'environments':[{'name':'aws-plan'}]} for s in ('approved','rejected')]
        with self.assertRaises(Exception):cli.github_evidence(env,get=lambda p:reviews if p.endswith('/approvals') else {'protected':True,'commit':{'sha':env['GITHUB_SHA']}})
    def test_network_unavailable_or_redirect_cannot_fall_back(self):
        with self.assertRaises(Exception):cli.github_evidence(environment(),get=lambda p: (_ for _ in ()).throw(OSError('unavailable')))
        with self.assertRaises(Exception):cli.NoRedirect().redirect_request(None,None,None,None,None,None)
        with patch.object(cli,'build_opener') as opener,self.assertRaises(Exception):cli.github_evidence(dict(environment(),GH_TOKEN=''))
        opener.assert_not_called()
    def test_checked_in_template_cannot_activate(self):
        with self.assertRaises(Exception):a.validate_grant(json.loads((ROOT/'security/planning-authorization.template.json').read_text()))

    def test_midnight_and_window_end_have_conservative_admission_margin(self):
        late=datetime(2026,11,25,23,30,tzinfo=timezone.utc).timestamp()
        with self.assertRaises(Exception):self.reserve(now=late)
        near_end=a.timestamp(self.g['expires_at'])-2399
        with self.assertRaises(Exception):self.reserve(now=near_end)
    def test_separate_processes_cannot_double_reserve(self):
        import subprocess
        code="import json,sys;sys.path.insert(0,'scripts');from cloudguard.authorization import Ledger\ntry: Ledger(sys.argv[1]).reserve(sys.argv[2],json.loads(sys.argv[3]),float(sys.argv[4]));sys.exit(0)\nexcept Exception:sys.exit(3)"
        def work(i):return subprocess.run([sys.executable,'-c',code,str(self.path),str(i),json.dumps(self.g['scope']),str(NOW)],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30).returncode
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(work,range(1,5)))
        self.assertEqual(results.count(0),1);self.assertEqual(results.count(3),3)

    def test_self_review_requires_explicit_fresh_grant_exception(self):
        env=environment();reviews=[{'state':'approved','user':{'type':'User','login':'dispatcher'},'environments':[{'name':'aws-plan'}]}]
        get=lambda p:reviews if p.endswith('/approvals') else {'protected':True,'commit':{'sha':env['GITHUB_SHA']}}
        with self.assertRaises(Exception):cli.github_evidence(env,get=get)
        cli.github_evidence(env,get=get,allow_self_review=True)
        with self.assertRaises(Exception):cli.github_evidence(env,get=get,allow_self_review='true')
