"""Offline exact trust and consumed-approval regressions. Never request tokens."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import ci_security as c

SUBJECT='repo:YenumulaAashish@212769106/cloudguard-ai@1379194368:environment:aws-plan'

class OidcSubjectTests(unittest.TestCase):
    def test_exact_confirmed_subject_and_audience(self):
        text=(ROOT/'bootstrap/aws-plan-role/main.tf').read_text()
        trust=text.split('assume_role_policy = jsonencode(',1)[1].split('\n  tags =',1)[0]
        self.assertEqual(trust.count('token.actions.githubusercontent.com:sub'),1)
        self.assertIn('"token.actions.githubusercontent.com:sub" = "'+SUBJECT+'"',trust)
        self.assertIn('"token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"',trust)
        self.assertIn('StringEquals = {',trust)
        self.assertNotIn('StringLike',trust);self.assertNotIn('*',trust)
        self.assertIn('Principal = { Federated = var.github_oidc_provider_arn }',trust)

    def test_cli_guard_rejects_trust_or_permission_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in c.FILES.values():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            target=root/'bootstrap/aws-plan-role/main.tf';original=target.read_text()
            self.assertEqual(c.verify(root)['result'],'PASS')
            mutations=[(SUBJECT,SUBJECT.replace('@212769106','').replace('@1379194368','')),
                       ('@1379194368','@1379194369'),('sts.amazonaws.com','other-audience'),
                       ('StringEquals','StringLike'),(':environment:aws-plan',':environment:*'),
                       ('"s3:ListBucket"','"s3:*"')]
            for before,after in mutations:
                target.write_text(original.replace(before,after))
                with self.subTest(change=after):
                    self.assertIn('BOOTSTRAP_ROLE_CONTRACT_CHANGED',c.verify(root)['errors'])

    def test_main_environment_and_enable_guards_are_unchanged(self):
        flow=c.load_yaml((ROOT/'.github/workflows/terraform-plan.yml').read_text())
        self.assertEqual(set(flow['on']),{'workflow_dispatch'})
        job=flow['jobs']['plan'];self.assertEqual(job['environment'],'aws-plan')
        for condition in ["github.ref == 'refs/heads/main'","vars.AWS_PLAN_ENABLED == 'true'","vars.AWS_PLAN_REVIEW_APPROVED == 'true'","github.repository == 'YenumulaAashish/cloudguard-ai'"]:
            self.assertIn(condition,job['if'])
        self.assertEqual(job['permissions'],{'contents':'read','id-token':'write'})

    def test_fresh_approval_has_no_inherited_authorization(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        self.assertEqual(r['id'],'CG-SM-PLAN-002');self.assertEqual(r['status'],'PENDING_OWNER_APPROVAL')
        self.assertEqual(r['supersedes_consumed'],'CG-SM-PLAN-001')
        for key in ['approver','approval_source','approval_date','expires_at','reviewed_fix_commit','pull_request','protected_main_sha']:
            self.assertIsNone(r[key])
        self.assertFalse(r['retry_authorized']);self.assertEqual(r['maximum_plan_runs'],1)
        self.assertEqual(r['execution_status'],'NOT RUN')
        old=json.loads((ROOT/'security/maintainer-planning-exception.json').read_text())
        self.assertEqual(r['preserved_controls'],old['preserved_controls'])
        self.assertEqual(r['prohibited_operations'],old['prohibited_operations'])

    def test_failed_attempt_is_consumed_without_claiming_live_success(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception.json').read_text())
        self.assertEqual(r['status'],'CONSUMED');self.assertFalse(r['retry_authorized'])
        self.assertEqual(r['execution_status'],'FAILED_OIDC_AUTHENTICATION')
        self.assertEqual(r['consumed_by_run'],'45469018350')
        self.assertIn('CloudTrail',r['consumption_evidence'])

    def test_current_docs_match_subject_and_incident(self):
        for name in ['docs/github-oidc.md','docs/oidc-subject-mismatch.md','bootstrap/aws-plan-role/README.md']:
            text=(ROOT/name).read_text()
            self.assertIn(SUBJECT,text)
        text=(ROOT/'docs/oidc-subject-mismatch.md').read_text()
        for expected in ['45469018350','AccessDenied','StringEquals','PENDING_OWNER_APPROVAL','NOT RUN']:
            self.assertIn(expected,text)
