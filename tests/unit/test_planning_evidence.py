"""Exit-code and leakage tests use synthetic data, never AWS credentials."""
import json
from pathlib import Path
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from cloudguard.planning import plan_exit_success
from cloudguard.evidence import plan_summary, policy_summary

class PlanningTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertTrue(plan_exit_success(0))
        self.assertTrue(plan_exit_success(2))
        for code in (1, -1, 3):
            self.assertFalse(plan_exit_success(code))

    def test_summary_strips_values_and_counts_replacements(self):
        plan = {'format_version': '1.2', 'terraform_version': '1.9.8', 'planned_values': {'root_module': {}},
                'resource_changes': [{'address': 'aws_example.test', 'type': 'aws_example', 'change': {
                    'actions': ['delete', 'create'], 'before': {'secret': 'NEVER_EXPORT'}, 'after': {'secret': 'NEVER_EXPORT'},
                    'after_sensitive': {'secret': True}}}], 'variables': {'password': {'value': 'NEVER_EXPORT'}}}
        summary = plan_summary(plan, 2)
        self.assertEqual(summary['counts']['create'], 1)
        self.assertEqual(summary['counts']['delete'], 1)
        self.assertNotIn('NEVER_EXPORT', json.dumps(summary))
        self.assertNotIn('after', json.dumps(summary))

    def test_failed_or_incomplete_plan_is_not_success(self):
        for plan, code in (({}, 1), ({}, 0), ({'format_version': '2.0'}, 2)):
            with self.assertRaises(ValueError):
                plan_summary(plan, code)

    def test_policy_summary_strips_sensitive_messages(self):
        rows = [{'filename': 'PRIVATE_PATH', 'successes': 0, 'failures': [{'msg': 'NEVER_EXPORT', 'metadata': {'secret': 'SECRET'}}]}]
        summary = policy_summary(rows, 1)
        self.assertEqual(summary['result'], 'FAIL')
        for value in ('PRIVATE_PATH', 'NEVER_EXPORT', 'SECRET'):
            self.assertNotIn(value, json.dumps(summary))

    def test_policy_error_cannot_pass(self):
        with self.assertRaises(ValueError):
            policy_summary([], 0)
        with self.assertRaises(ValueError):
            policy_summary([{'successes': 1, 'failures': [{'msg': 'bad'}]}], 0)


class PlanProcessTests(unittest.TestCase):
    def test_process_flow_for_zero_one_and_two(self):
        from cloudguard import planning
        document = {"format_version": "1.2", "terraform_version": "1.9.8",
                    "planned_values": {"root_module": {}}, "resource_changes": []}
        for code in (0, 1, 2):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "terraform").mkdir()
                records, calls = {}, []
                def fake_run(args, **kwargs):
                    calls.append(args)
                    if "show" in args:
                        json.dump(document, kwargs["stdout"])
                    return SimpleNamespace(returncode=code if "plan" in args else 0)
                with patch.object(planning, "ROOT", root), patch.object(planning, "PRIVATE", root / "private"), \
                     patch.object(planning, "tool", return_value=["terraform"]), \
                     patch.object(planning, "run", side_effect=fake_run), \
                     patch.object(planning, "record", side_effect=lambda key, value: records.update({key: value})):
                    self.assertEqual(planning.create_plan(), code in (0, 2))
                self.assertEqual(any("show" in args for args in calls), code in (0, 2))
                self.assertEqual(records["plan-summary"]["result"], "FAIL" if code == 1 else "PASS")
                self.assertEqual(records["plan-summary"]["exit_code"], code)

    def test_failed_json_export_blocks(self):
        from cloudguard import planning
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "terraform").mkdir()
            records = {}
            def fake_run(args, **kwargs):
                return SimpleNamespace(returncode=1 if "show" in args else 0)
            with patch.object(planning, "ROOT", root), patch.object(planning, "PRIVATE", root / "private"), \
                 patch.object(planning, "tool", return_value=["terraform"]), \
                 patch.object(planning, "run", side_effect=fake_run), \
                 patch.object(planning, "record", side_effect=lambda key, value: records.update({key: value})):
                self.assertFalse(planning.create_plan())
            self.assertEqual(records["plan-summary"]["result"], "FAIL")


class EvidenceFreshnessTests(unittest.TestCase):
    def test_missing_and_stale_results_never_pass(self):
        from cloudguard import evidence
        with patch.object(evidence, "read_json", side_effect=FileNotFoundError):
            self.assertEqual(evidence.load("checks")["result"], "NOT RUN")
        with patch.object(evidence, "read_json", return_value={"result": "PASS", "run_id": "old"}), \
             patch.object(evidence, "context", return_value={"run_id": "new"}):
            self.assertEqual(evidence.load("checks")["result"], "NOT RUN")
        with patch.object(evidence, "read_json", return_value={"result": "PASS", "run_id": "same", "source_digest": "old"}), \
             patch.object(evidence, "context", return_value={"run_id": "same"}), \
             patch.object(evidence, "fingerprint", return_value="new"):
            self.assertEqual(evidence.load("checks")["result"], "NOT RUN")
