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

    def test_fresh_approval_has_explicit_owner_authorization_and_known_bindings(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        self.assertEqual(r['id'],'CG-SM-PLAN-002');self.assertEqual(r['status'],'CONSUMED')
        self.assertEqual(r['supersedes_consumed'],'CG-SM-PLAN-001')
        self.assertEqual(r['approver'],'YenumulaAashish (repository owner)')
        self.assertEqual(r['approval_date'],'2026-11-25')
        self.assertEqual(r['expires_at'],'2026-12-01T18:30:00Z')
        self.assertIn('explicit approval',r['approval_source'])
        self.assertEqual(r['reviewed_fix_commit'],'b7b71ea7c60dceaa69991acb17bc319448bb385d')
        self.assertEqual(r['protected_main_sha'],'ccc6adadf49cade9be2cd801fab42bc8cf67f004')
        self.assertEqual(r['reviewed_baseline'],r['protected_main_sha'])
        self.assertEqual(r['proposal_baseline'],'4de89ebab07defa44f48b4ab61a1fa48b7331830')
        self.assertEqual(r['pull_request'],'https://github.com/YenumulaAashish/cloudguard-ai/pull/3')
        self.assertFalse(r['retry_authorized']);self.assertEqual(r['maximum_plan_runs'],1)
        self.assertEqual(r['execution_status'],'FAILED_SECURITY_VERDICT')
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
        for expected in ['45469018350','AccessDenied','StringEquals','APPROVED_RESTRICTED_SCOPE','NOT RUN']:
            self.assertIn(expected,text)

    def test_amendment_does_not_fabricate_future_execution_bindings(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        self.assertEqual(r['execution_readiness'],'CONSUMED_NO_RETRY')
        self.assertFalse(r['execution_authorized_by_this_task'])
        self.assertTrue(all(v is None for v in r['amendment_bindings'].values()))
        self.assertEqual(r['approved_review_exceptions'],['environment self-review'])
        self.assertIn('absence of independent CODEOWNERS approval',r['unapproved_review_exceptions'])

    def test_evidence_provenance_is_explicit_and_missing_urls_stay_missing(self):
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        evidence=r['owner_confirmed_evidence']
        self.assertFalse(evidence['independently_verified'])
        self.assertEqual(evidence['required_pr_check_result'],'PASS')
        self.assertEqual(evidence['latest_main_hosted_offline_ci'],'PASS')
        self.assertIsNone(evidence['required_pr_check_run_url']);self.assertIsNone(evidence['main_offline_run_url'])
        self.assertTrue(r['independently_verified_evidence']['fix_is_ancestor_of_merge'])
        self.assertFalse(r['independently_verified_evidence']['remote_ref_freshness_verified'])

    def test_new_approval_documents_require_final_bindings_and_unchanged_authority(self):
        text=(ROOT/'docs/plan-002-approval.md').read_text()
        for value in ['2026-12-01T18:30:00Z','owner-confirmed','BLOCKED_FINAL_AMENDMENT_BINDINGS','NOT RUN','No independent PR approval']:
            self.assertIn(value.lower(),text.lower())
        r=json.loads((ROOT/'security/maintainer-planning-exception-002.json').read_text())
        for prohibited in ['Terraform apply','Terraform destroy','state mutation','privileged Phase 6 operations']:
            self.assertIn(prohibited,r['prohibited_operations'])
