"""Record consistency only: these tests do not grant or execute cloud access."""
import json
from datetime import datetime, timezone
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))

class PlanningApprovalTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT/'security/maintainer-planning-exception.json').read_text())

    def test_explicit_owner_and_pr_binding(self):
        r=self.record
        self.assertEqual(r['status'],'CONSUMED')
        self.assertEqual(r['consumed_by_run'],'45469018350')
        self.assertIs(r['retry_authorized'],False)
        self.assertEqual(r['id'],'CG-SM-PLAN-001')
        self.assertEqual(r['approver'],'YenumulaAashish (repository owner)')
        self.assertEqual(r['reviewed_baseline'],'bb97a1d6bbb7826c9ddd7501ea26ab909959b198')
        self.assertEqual(r['pull_request'],'https://github.com/YenumulaAashish/cloudguard-ai/pull/2')
        self.assertIn('consistency-test amendment only',r['amendments_allowed'])

    def test_conservative_expiry_and_single_use(self):
        r=self.record
        self.assertEqual(r['approval_date'],'2026-11-25')
        self.assertEqual(r['approval_time_precision'],'date_only')
        self.assertEqual(datetime.fromisoformat(r['expires_at'].replace('Z','+00:00')),datetime(2026,12,1,18,30,tzinfo=timezone.utc))
        self.assertEqual(r['maximum_plan_runs'],1)
        self.assertTrue(any('terminal outcome' in s for s in r['revocation_conditions']))
        self.assertTrue(any('owner revokes' in s for s in r['revocation_conditions']))

    def test_review_exception_is_not_deployment_authority(self):
        self.assertEqual(set(self.record['review_exceptions']),{'environment self-review','absence of independent PR approval','absence of independent CODEOWNERS approval'})
        for forbidden in ['Terraform apply','Terraform destroy','privileged Phase 6 operations','AWS resource or IAM modification','bypass of automated gates']:
            self.assertIn(forbidden,self.record['prohibited_operations'])
        self.assertEqual(self.record['execution_status'],'FAILED_OIDC_AUTHENTICATION')
        for field in ['github_settings_changed','aws_variables_enabled','aws_contacted']:
            self.assertIs(self.record[field],False)

    def test_documents_agree_on_consumed_scope_and_pending_retry(self):
        for name in ['README.md','docs/github-oidc.md','docs/phase5-integration.md']:
            text=(ROOT/name).read_text(encoding='utf-8')
            self.assertIn('CG-SM-PLAN-001',text)
            self.assertIn('2026-12-01T18:30:00Z',text)
            self.assertIn('CONSUMED',text)
            self.assertIn('CG-SM-PLAN-002',text)
            self.assertIn('APPROVED_RESTRICTED_SCOPE',text)

    def test_automated_gates_and_trust_remain_intact(self):
        from cloudguard.ci_security import verify
        from cloudguard.safety import inspect
        self.assertEqual(verify(ROOT)['result'],'PASS')
        self.assertEqual(inspect(ROOT),[])
        self.assertEqual(inspect(ROOT,suppression=True),[])

    def test_pending_final_binding_and_restoration(self):
        self.assertIn('record final PR head and protected main SHA',self.record['remaining_execution_prerequisites'])
        self.assertEqual(self.record['restoration_owner'],'YenumulaAashish')
        self.assertTrue(any('permission validation fails' in s for s in self.record['revocation_conditions']))
