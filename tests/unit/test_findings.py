"""Phase 3.1 adapters, CLI, determinism and private-output boundary."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from cloudguard.findings import (FindingInputError, build_report, normalize_checkov,
                                 normalize_conftest, serialize)
from cloudguard.exceptions import REVIEWED

FIXTURES = ROOT / "tests/fixtures/normalization"


def fixture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())


def empty_checkov():
    raw = fixture("checkov")
    for group in ("passed_checks", "failed_checks", "skipped_checks"):
        raw["results"][group] = []
    raw["summary"].update(passed=0, failed=0, skipped=0)
    return raw


class FindingTests(unittest.TestCase):
    def test_checkov_failure_and_reviewed_skip(self):
        failed, skipped = normalize_checkov(fixture("checkov"))
        self.assertEqual((failed["status"], failed["severity"], failed["exception"]),
                         ("failed", "HIGH", False))
        self.assertEqual((failed["file"], failed["line"], failed["line_end"]), ("/main.tf", 10, 16))
        self.assertEqual((skipped["status"], skipped["exception"]), ("skipped", True))

    def test_all_six_reviewed_pairs_and_unapproved_skip(self):
        raw = empty_checkov()
        raw["results"]["skipped_checks"] = [
            {"check_id": rule, "resource": resource, "check_result": {"result": "SKIPPED"}}
            for rule, resource in sorted(REVIEWED)]
        raw["summary"]["skipped"] = 6
        self.assertTrue(all(f["exception"] for f in normalize_checkov(raw)))
        raw["results"]["skipped_checks"][0]["resource"] = "aws_s3_bucket.other"
        self.assertFalse(normalize_checkov(raw)[0]["exception"])

    def test_failed_reviewed_pair_is_still_failed(self):
        raw = fixture("checkov")
        raw["results"]["failed_checks"][0]["resource"] = "module.storage.aws_s3_bucket.this"
        failed = normalize_checkov(raw)[0]
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(failed["exception"])

    def test_missing_optional_fields_are_null(self):
        raw = fixture("checkov")
        raw["results"]["failed_checks"] = [{"check_id": "CKV_AWS_18", "check_result": {"result": "FAILED"}}]
        failed = normalize_checkov(raw)[0]
        for field in ("resource", "file", "line", "line_end", "message"):
            self.assertIsNone(failed[field])
        self.assertEqual(failed["severity"], "UNKNOWN")

    def test_severity_is_explicit_and_never_inferred_from_control(self):
        for value, expected in ((None, "UNKNOWN"), ("", "UNKNOWN"), ("high", "HIGH"),
                                ("critical", "CRITICAL"), ("medium", "MEDIUM"),
                                ("low", "LOW"), ("info", "INFO"), ("urgent", "UNKNOWN")):
            with self.subTest(value=value):
                raw = fixture("checkov")
                raw["results"]["failed_checks"][0]["severity"] = value
                self.assertEqual(normalize_checkov(raw)[0]["severity"], expected)

    def test_complete_empty_scan_and_successful_conftest_have_no_findings(self):
        report = build_report([("checkov", empty_checkov()), ("conftest", [
            {"filename": "baseline.json", "namespace": "main", "successes": 13}])])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["total"], 0)
        self.assertEqual(report["sources"], ["checkov", "conftest"])

    def test_multiple_sources_summary_and_canonical_order(self):
        inputs = [("checkov", fixture("checkov")), ("conftest", fixture("conftest"))]
        report = build_report(inputs)
        self.assertEqual(report["summary"], {"total": 3, "critical": 0, "high": 1,
                         "medium": 0, "low": 0, "info": 0, "unknown": 2,
                         "failed": 2, "warning": 0, "skipped": 1})
        self.assertEqual(serialize(report), serialize(build_report(list(reversed(inputs)))))
        self.assertNotIn("timestamp", serialize(report))

    def test_order_independence_and_duplicate_preservation(self):
        raw = fixture("conftest")
        raw[0]["failures"] *= 2
        raw[0]["failures"].append({"msg": "TAGS: aws_s3_bucket.a missing Project"})
        reverse = copy.deepcopy(raw)
        reverse[0]["failures"].reverse()
        a = build_report([("conftest", raw)])
        self.assertEqual(a["summary"]["total"], 3)
        self.assertEqual(serialize(a), serialize(build_report([("conftest", reverse)])))

    def test_private_extra_fields_are_not_copied(self):
        result = serialize(build_report([("checkov", fixture("checkov"))]))
        self.assertNotIn("NEVER_EXPORT", result)
        raw = fixture("conftest")
        raw[0]["failures"][0]["metadata"]["values"] = "NEVER_EXPORT"
        self.assertNotIn("NEVER_EXPORT", serialize(build_report([("conftest", raw)])))

    def test_checkov_wrapped_report_and_other_framework(self):
        self.assertEqual(normalize_checkov(fixture("checkov")),
                         normalize_checkov([{"check_type": "dockerfile"}, fixture("checkov")]))
        with self.assertRaises(FindingInputError):
            normalize_checkov([fixture("checkov"), fixture("checkov")])

    def test_malformed_or_incomplete_checkov_rejected(self):
        broken = []
        for field in ("summary", "results"):
            raw = fixture("checkov"); raw.pop(field); broken.append(raw)
        raw = fixture("checkov"); raw["summary"]["failed"] = 0; broken.append(raw)
        raw = fixture("checkov"); raw["summary"]["parsing_errors"] = 1; broken.append(raw)
        raw = fixture("checkov"); raw["results"]["passed_checks"] = {}; broken.append(raw)
        raw = fixture("checkov"); raw["results"]["failed_checks"][0]["check_result"]["result"] = "SKIPPED"; broken.append(raw)
        raw = fixture("checkov"); raw["results"]["failed_checks"][0]["file_line_range"] = [16, 10]; broken.append(raw)
        for raw in (None, [], {}, *broken):
            with self.subTest(raw=raw), self.assertRaises(FindingInputError):
                normalize_checkov(raw)

    def test_actual_conftest_format_and_location_semantics(self):
        item = normalize_conftest(fixture("conftest"))[0]
        self.assertEqual((item["control_id"], item["resource"]), ("SSH", "aws_security_group.test"))
        self.assertEqual(item["metadata"]["query"], "data.main.deny")
        self.assertEqual(item["severity"], "UNKNOWN")
        self.assertIsNone(item["file"])
        self.assertIsNone(item["line"])
        self.assertFalse(item["exception"])

    def test_policy_families_and_indexed_resource(self):
        messages = [
            ("IAM: aws_iam_policy.x allows wildcard actions", "IAM", "aws_iam_policy.x"),
            ("TAGS: aws_vpc.x missing Project", "TAGS", "aws_vpc.x"),
            ("S3_ENCRYPTION: aws_s3_bucket.x requires explicit known encryption", "S3_ENCRYPTION", "aws_s3_bucket.x"),
            ('S3_PUBLIC: module.app["key value"].aws_s3_bucket.x[0] enables a public ACL', "S3_PUBLIC", 'module.app["key value"].aws_s3_bucket.x[0]'),
            ("UNKNOWN: aws_vpc.x has unresolved security field tags", "UNKNOWN", "aws_vpc.x"),
            ("INPUT: expected Terraform plan JSON with planned_values.root_module", "INPUT", None),
            ("SSH: an unfamiliar future format", "SSH", None),
            ("Future policy message", "data.main.deny", None),
        ]
        for message, control, resource in messages:
            raw = fixture("conftest"); raw[0]["failures"][0]["msg"] = message
            item = normalize_conftest(raw)[0]
            self.assertEqual((item["control_id"], item["resource"]), (control, resource))

    def test_unknown_message_without_query_has_no_invented_id(self):
        raw = fixture("conftest")
        raw[0]["failures"] = [{"msg": "Custom message"}]
        item = normalize_conftest(raw)[0]
        self.assertIsNone(item["control_id"])
        self.assertIsNone(item["resource"])

    def test_warning_is_not_failure(self):
        raw = fixture("conftest")
        raw[0]["warnings"] = raw[0].pop("failures")
        report = build_report([("conftest", raw)])
        self.assertEqual(report["summary"]["warning"], 1)
        self.assertEqual(report["summary"]["failed"], 0)

    def test_conftest_errors_exceptions_and_opa_tests_rejected(self):
        broken = [None, {}, [], [{"name": "test_ssh", "fail": True}]]
        for field in ("errors", "exceptions"):
            raw = fixture("conftest"); raw[0][field] = [{"msg": "Error"}]; broken.append(raw)
        raw = fixture("conftest"); raw[0]["failures"] = "invalid"; broken.append(raw)
        raw = fixture("conftest"); raw[0]["successes"] = True; broken.append(raw)
        raw = fixture("conftest"); raw[0]["failures"][0]["metadata"] = ["bad"]; broken.append(raw)
        raw = fixture("conftest"); raw[0]["failures"][0]["metadata"] = []; broken.append(raw)
        for raw in broken:
            with self.subTest(raw=raw), self.assertRaises(FindingInputError):
                normalize_conftest(raw)

    def test_unsupported_sources_and_no_inputs(self):
        for inputs in ([], [("terraform", {})], [("opa-test", [])]):
            with self.assertRaises(FindingInputError):
                build_report(inputs)


class FindingCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts/normalize-findings.py"), *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT)

    def test_help_and_required_source(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        self.assertEqual(self.run_cli().returncode, 2)

    def test_findings_do_not_become_a_security_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out.json"
            result = self.run_cli("--checkov", FIXTURES / "checkov.json", "--output", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(path.read_text())["summary"]["failed"], 1)
            self.assertNotIn("NEVER_EXPORT", result.stdout + result.stderr)

    def test_existing_output_and_input_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            text = (FIXTURES / "checkov.json").read_text(); path.write_text(text)
            result = self.run_cli("--checkov", path, "--output", path)
            self.assertEqual(result.returncode, 2)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(path.read_text(), text)
            self.assertEqual(list(Path(directory).glob(".findings-*")), [])

    def test_bad_inputs_never_leave_output_or_echo_values(self):
        values = ['{"secret": "NEVER_EXPORT",', '{"x": 1, "x": 2}', '{"x": NaN}', '{}']
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "in.json", Path(directory) / "out.json"
            for value in values:
                source.write_text(value)
                result = self.run_cli("--checkov", source, "--output", destination)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(destination.exists())
                self.assertNotIn("NEVER_EXPORT", result.stdout + result.stderr)
            self.assertEqual(self.run_cli("--conftest", source.with_name("missing"), "--output", destination).returncode, 2)

    def test_cli_deterministic_bytes_and_multiple_input_files(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = [Path(directory) / "a.json", Path(directory) / "b.json"]
            for output in outputs:
                result = self.run_cli("--checkov", FIXTURES / "checkov.json", "--conftest",
                                      FIXTURES / "conftest.json", "--output", output)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())


class LiveFixtureTests(unittest.TestCase):
    def test_installed_conftest_output_when_available(self):
        from cloudguard.runtime import tool
        try:
            executable = tool("conftest")
        except FileNotFoundError:
            self.skipTest("Conftest unavailable; deterministic fixture tests still run")
        result = subprocess.run(executable + ["test", "tests/fixtures/insecure/public-ssh.json",
                                "--policy", "policies/terraform", "--output", "json"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, "Conftest did not reject the insecure fixture")
        items = normalize_conftest(json.loads(result.stdout))
        self.assertTrue(items)
        self.assertTrue(all(f["status"] == "failed" and f["control_id"] == "SSH" for f in items))
