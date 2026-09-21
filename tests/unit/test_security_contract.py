"""Negative controls for the exception invariant and executable CI safety."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from cloudguard.exceptions import REVIEWED, verify
from cloudguard.source import annotations
from cloudguard.safety import inspect


def scan():
    skipped = [{"check_id": a, "resource": b, "check_result": {"result": "SKIPPED"}} for a, b in REVIEWED]
    return {"check_type": "terraform", "summary": {"passed": 1, "failed": 0, "skipped": len(skipped), "parsing_errors": 0, "resource_count": 1},
            "results": {"passed_checks": [{"check_id": "CKV_TEST", "resource": "aws_test.good", "check_result": {"result": "PASSED"}}], "failed_checks": [], "skipped_checks": skipped}}


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ("terraform", "security"):
            shutil.copytree(ROOT / name, self.root / name, ignore=shutil.ignore_patterns(".terraform", "tfplan*"))
        (self.root / "scripts").mkdir()
        (self.root / ".github/workflows").mkdir(parents=True)
        shutil.copy(ROOT / ".checkov.yml", self.root / ".checkov.yml")
        self.raw = scan()

    def tearDown(self):
        self.tmp.cleanup()

    def result(self):
        return verify(self.root, self.raw)

    def test_exact_contract_passes(self):
        self.assertEqual(self.result()["result"], "PASS")

    def test_new_inline_skip_fails(self):
        p = self.root / "terraform/modules/storage/main.tf"
        p.write_text(p.read_text().replace('resource "aws_s3_bucket" "this" {', 'resource "aws_s3_bucket" "this" {\n #checkov:skip=CKV_NEW:unreviewed'))
        self.assertEqual(self.result()["result"], "FAIL")

    def test_missing_annotation_fails(self):
        p = self.root / "terraform/modules/network/main.tf"
        p.write_text('\n'.join(line for line in p.read_text().splitlines() if 'checkov:skip' not in line))
        self.assertTrue(self.result()["missing"])

    def test_annotation_moved_to_other_resource_fails(self):
        p = self.root / "terraform/modules/network/main.tf"
        p.write_text(p.read_text().replace('resource "aws_vpc" "this"', 'resource "aws_vpc" "other"'))
        self.assertTrue(self.result()["unexpected"])

    def test_duplicate_annotation_fails(self):
        p = self.root / "terraform/modules/network/main.tf"
        s = p.read_text()
        comment = next(line for line in s.splitlines() if 'checkov:skip' in line)
        p.write_text(s.replace(comment, comment + '\n' + comment))
        self.assertEqual(self.result()["result"], "FAIL")

    def test_global_configuration_fails(self):
        for setting in ('skip-check: [CKV_TEST]', 'soft-fail: true', 'soft-fail-on: [LOW]'):
            with self.subTest(setting=setting):
                (self.root / '.checkov.yml').write_text(setting)
                self.assertTrue(self.result()['global_suppression_detected'])

    def test_script_and_workflow_flags_fail(self):
        for name in ('scripts/bad.sh', '.github/workflows/bad.yml'):
            for flag in ('--soft-fail', '--skip-check CKV_TEST'):
                with self.subTest(name=name, flag=flag):
                    (self.root / name).write_text('checkov -d terraform ' + flag)
                    self.assertTrue(self.result()['global_suppression_detected'])
            (self.root / name).unlink()

    def test_skip_disguised_as_pass_fails(self):
        item = self.raw['results']['skipped_checks'].pop()
        item['check_result']['result'] = 'PASSED'
        self.raw['results']['passed_checks'].append(item)
        self.raw['summary'].update(passed=2, skipped=5)
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_failure_is_not_allowed_even_for_exception(self):
        item = self.raw['results']['skipped_checks'].pop()
        item['check_result']['result'] = 'FAILED'
        self.raw['results']['failed_checks'].append(item)
        self.raw['summary'].update(failed=1, skipped=5)
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_unaccepted_failure_fails(self):
        self.raw['results']['failed_checks'] = [{'check_id': 'CKV_NEW', 'resource': 'x', 'check_result': {'result': 'FAILED'}}]
        self.raw['summary']['failed'] = 1
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_truncated_report_fails(self):
        del self.raw['results']['skipped_checks']
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_seventh_json_exception_fails(self):
        p = self.root / 'security/checkov-exceptions.json'
        doc = json.loads(p.read_text())
        doc['exceptions'].append({'rule_id': 'NEW', 'resource': 'x', 'rationale': 'x', 'review_trigger': 'x'})
        p.write_text(json.dumps(doc))
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_json_count_tampering_fails(self):
        self.raw['summary']['skipped'] = 0
        self.assertEqual(self.result()['result'], 'FAIL')

    def test_deployment_commands_and_safe_docs(self):
        (self.root / 'README.md').write_text('Never run terraform apply or terraform destroy.')
        self.assertFalse(inspect(self.root))
        for command in ('terraform apply', 'terraform -chdir=terraform destroy', 'terraform apply -auto-approve'):
            (self.root / 'scripts/bad.sh').write_text(command)
            self.assertTrue(inspect(self.root))
        (self.root / 'scripts/bad.sh').unlink()
        (self.root / 'scripts/bad.py').write_text('import subprocess\nsubprocess.run(["terraform", "apply"])')
        self.assertTrue(inspect(self.root))


    def test_nested_global_configuration_fails(self):
        (self.root / 'security/scan.yml').write_text('skip-check: [CKV_TEST]')
        self.assertTrue(self.result()['global_suppression_detected'])

    def test_python_helper_deployment_command_fails(self):
        (self.root / 'scripts/bad.py').write_text('run(tool("terraform") + ["apply"])')
        self.assertTrue(inspect(self.root))

    def test_failure_masking_workflow_fails(self):
        (self.root / '.github/workflows/bad.yml').write_text('continue-on-error: true')
        self.assertTrue(inspect(self.root))

    def test_nonobject_report_fails_closed(self):
        for raw in ([], [None], 'invalid', {'results': {}}):
            self.assertEqual(verify(self.root, raw)['result'], 'FAIL')


    def test_bootstrap_cannot_add_a_seventh_exception(self):
        folder = self.root / 'bootstrap/aws-plan-role'
        folder.mkdir(parents=True)
        (folder / 'main.tf').write_text('resource "aws_iam_role" "x" {\n #checkov:skip=CKV_NEW:no\n}')
        self.assertEqual(self.result()['result'], 'FAIL')
