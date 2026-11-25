"""Catalog privacy, bounded policy reasons and backward-compatible report tests."""
import json
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import iam,network,data_protection,phase5
from cloudguard.control_catalog import describe
from cloudguard.live_advisory import Service,FIELDS,AdvisoryError
from cloudguard.policy_reporting import TEMPLATES,validate_reasons

class HardeningTests(unittest.TestCase):
    def test_catalog_exactly_covers_existing_controls_and_frontend_parity(self):
        c=json.loads((ROOT/'security/control-descriptions.json').read_text())
        self.assertEqual(c,json.loads((ROOT/'frontend/src/data/control-descriptions.json').read_text()))
        expected={**iam.CONTROLS,**network.CONTROLS,**data_protection.CONTROLS};self.assertEqual(set(c['controls']),set(expected))
        for control,row in c['controls'].items():
            self.assertEqual(row['description'],expected[control][1]);self.assertEqual(set(row),{'domain','description','reason_code','terraform_guidance','limitations'})
            self.assertRegex(row['reason_code'],r'^[A-Z0-9_]+$');self.assertLess(len(row['terraform_guidance']),400)
    def test_unknown_control_and_wrong_domain_are_not_guessed(self):
        for control,domain in [('CGA_DATA_999','data'),('CGA_DATA_011','iam'),('PRIVATE_CANARY','network')]:
            with self.assertRaises(ValueError):describe(control,domain)
    def test_static_context_is_copy_and_unknown_never_passes(self):
        row=describe('CGA_DATA_011','data');self.assertIn('UNKNOWN',row['terraform_guidance'])
        row['description']='mutated';self.assertNotEqual(describe('CGA_DATA_011','data')['description'],'mutated')
    def test_provider_receives_only_static_context_and_safe_fields(self):
        provider=Mock(return_value={k:'Review the supported static configuration.' for k in FIELDS})
        s=Service(provider,key='synthetic-test-key');before=deepcopy(s.findings)
        s.explain({'finding_id':s.findings[0]['id']})
        body=provider.call_args.args[0];self.assertEqual(set(body),{'control_id','domain','severity','status','resource_type','control_context','source','context_status'})
        self.assertEqual(body['control_context'],describe(body['control_id'],body['domain']));self.assertEqual(body['context_status'],'UNKNOWN')
        self.assertEqual(s.findings,before)
        for key in ('resource','message','policy','account','plan','catalog_id'):self.assertNotIn(key,body)
    def test_unsupported_control_fails_without_provider_call(self):
        provider=Mock();s=Service(provider,key='synthetic-test-key');s.findings[0]['control_id']='CGA_NET_999'
        with self.assertRaisesRegex(AdvisoryError,'AI_UNSUPPORTED_CONTROL'):s.explain({'finding_id':s.findings[0]['id']})
        provider.assert_not_called()
    def test_reason_pair_parity_and_negative_shape(self):
        pairs={(a,b) for a,b,_ in TEMPLATES}|{('UNMAPPED','UNRECOGNIZED_POLICY_MESSAGE')}
        self.assertEqual(pairs,{tuple(p) for p in json.loads((ROOT/'frontend/src/data/policy-reasons.json').read_text())})
        row={'rule_id':'UNKNOWN','reason_code':'UNRESOLVED_SECURITY_FIELD','count':1};validate_reasons([row])
        for bad in [[dict(row,message='PRIVATE_CANARY')],[dict(row,rule_id='SECRET')],[dict(row,count=0)],[dict(row,count=True)],[row,row]]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_reasons(bad)
    def test_legacy_bundle_and_new_unknown_reason_handling(self):
        b=json.loads((ROOT/'frontend/src/test/plan-demo.json').read_text());phase5.validate_bundle(b)
        b['version']='1.2';b['policy_reasons']=[];phase5.validate_bundle(b)
        b['policy_reasons']=[{'rule_id':'UNKNOWN','reason_code':'UNRESOLVED_SECURITY_FIELD','count':1}]
        with self.assertRaises(ValueError):phase5.validate_bundle(b)
        b['source']=b['findings']['source']='AUTHENTICATED_PLAN';b['pr']['policy']['opa_conftest']='FAIL';phase5.validate_bundle(b)
        b['policy_reasons'][0]['reason_code']='PRIVATE_CANARY'
        with self.assertRaises(ValueError):phase5.validate_bundle(b)
    def test_workflow_orders_reservation_before_credentials_and_disables_retries(self):
        from cloudguard.ci_security import load_yaml
        w=load_yaml((ROOT/'.github/workflows/terraform-plan.yml').read_text());j=w['jobs']['plan'];steps=j['steps']
        self.assertEqual(w['concurrency']['cancel-in-progress'],'false')
        self.assertEqual(j['runs-on'],['self-hosted','linux','x64','cloudguard-readonly-plan'])
        reserve=next(i for i,s in enumerate(steps) if s.get('run')=='python scripts/planning-authorization.py reserve')
        auth=next(i for i,s in enumerate(steps) if 'configure-aws-credentials@' in s.get('uses',''))
        self.assertLess(reserve,auth);self.assertEqual(steps[auth]['with']['disable-retry'],'true')
        self.assertEqual(steps[auth]['with']['retry-max-attempts'],'1')
        self.assertEqual(j['environment'],'aws-plan');self.assertEqual(j['permissions']['actions'],'read')
