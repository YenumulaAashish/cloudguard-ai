"""Realistic provider-shaped fixtures, not recordings of private AWS plans."""
import json
from copy import deepcopy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import data_protection as d, security_graph as g
from cloudguard.evidence import policy_summary

def fixture(name='computed-s3'):
    return json.loads((ROOT/'tests/fixtures/realistic-plan'/f'{name}.json').read_text())
def states(p):return {c['category']:c['state'] for c in d.analyze(p)['checks']}

class RealPlanContextTests(unittest.TestCase):
    def test_consumed_real_attempt_separates_milestones_from_verdict(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        self.assertEqual(r['status'],'CONSUMED');self.assertFalse(r['retry_authorized'])
        self.assertEqual(r['consumed_by_run'],'45484703135')
        m=r['execution_milestones'];self.assertEqual(m['oidc_authentication'],'PASS')
        self.assertEqual(m['plan_exit_code'],2);self.assertEqual(m['conftest_failed'],1)
        self.assertEqual(r['execution_status'],'FAILED_SECURITY_VERDICT')
        self.assertIsNone(r['confirmed_failed_rule_id']);self.assertIsNone(r['confirmed_failed_reason_code'])

    def test_known_companions_survive_computed_legacy_readback(self):
        s=states(fixture())
        for category in ['pab','encryption','versioning','lifecycle']:self.assertEqual(s[category],'ESTABLISHED')
        self.assertEqual(s['acl'],'REVIEWED')
        for category in ['policy','transport','logging']:self.assertEqual(s[category],'UNKNOWN')

    def test_unknown_algorithm_cannot_establish_encryption(self):
        self.assertEqual(states(fixture('unknown-algorithm'))['encryption'],'UNKNOWN')

    def test_known_disabled_pab_still_reports_violation(self):
        report=d.analyze(fixture('public-block-disabled'))
        self.assertIn('CGA_DATA_001',[f['control_id'] for f in report['findings']])
        self.assertEqual(states(fixture('public-block-disabled'))['pab'],'WEAK')

    def test_unknown_companion_does_not_establish_protection(self):
        self.assertEqual(states(fixture('unknown-companion'))['pab'],'UNKNOWN')

    def test_unknown_ownership_does_not_resolve_acl(self):
        p=fixture();c=next(c for c in p['resource_changes'] if c['type']=='aws_s3_bucket_ownership_controls')
        c['change']['after_unknown']['rule']=True
        self.assertEqual(states(p)['acl'],'UNKNOWN')
        self.assertTrue(any(f['category']=='context' for f in d.analyze(p)['findings']))

    def test_additional_unresolved_ownership_prevents_acl_inference(self):
        p=fixture();c=deepcopy(next(c for c in p['resource_changes'] if c['type']=='aws_s3_bucket_ownership_controls'))
        c['address']='module.storage.aws_s3_bucket_ownership_controls.unresolved'
        c['change']['after'].pop('bucket');c['change']['after_unknown']['bucket']=True
        p['resource_changes'].append(c)
        self.assertEqual(states(p)['acl'],'UNKNOWN')

    def test_kms_unknown_remains_unknown(self):
        p=fixture();c=next(c for c in p['resource_changes'] if c['type']=='aws_s3_bucket_server_side_encryption_configuration')
        c['change']['after']['rule'][0]['apply_server_side_encryption_by_default'][0]['sse_algorithm']='aws:kms'
        self.assertEqual(states(p)['encryption'],'UNKNOWN')

    def test_unrecognized_encryption_unknown_is_not_ignored(self):
        p=fixture();c=next(c for c in p['resource_changes'] if c['type']=='aws_s3_bucket_server_side_encryption_configuration')
        c['change']['after_unknown']['rule'][0]['unrecognized_setting']=True
        self.assertEqual(states(p)['encryption'],'UNKNOWN')

    def test_reference_unknowns_are_not_inferred_from_names_or_dependencies(self):
        p=fixture();before=deepcopy(p);report=g.build(p)
        self.assertGreater(report['summary']['unresolved'],0)
        self.assertEqual(p,before)
        self.assertTrue(all(e['evidence']=='EXACT_KNOWN_VALUE' for e in report['edges']))

    def test_sanitized_reason_identifies_template_without_values(self):
        rows=[{'filename':'PRIVATE_PATH','successes':12,'failures':[{'msg':'UNKNOWN: aws_s3_bucket_server_side_encryption_configuration.PRIVATE_ID has unresolved security field rule','metadata':{'secret':'PRIVATE_SECRET'}}]}]
        result=policy_summary(rows,1)
        self.assertEqual(result['result'],'FAIL');self.assertEqual(result['failed'],1)
        self.assertEqual(result['failure_reasons'],[{'rule_id':'UNKNOWN','reason_code':'UNRESOLVED_SECURITY_FIELD','count':1}])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_unknown_messages_have_only_fixed_unmapped_reason(self):
        result=policy_summary([{'successes':0,'failures':[{'msg':'SECRET attacker data'}]}],1)
        self.assertEqual(result['failure_reasons'],[{'rule_id':'UNMAPPED','reason_code':'UNRECOGNIZED_POLICY_MESSAGE','count':1}])
        self.assertNotIn('SECRET',json.dumps(result))

    def test_reasons_are_bounded_and_aggregated_not_truncated_failures(self):
        result=policy_summary([{'successes':0,'failures':[{'msg':'S3_PUBLIC: private requires all four public access blocks'}]*100}],1)
        self.assertEqual(result['failed'],100);self.assertEqual(len(result['failure_reasons']),1)
        self.assertEqual(result['failure_reasons'][0]['count'],100)
