"""Risk prioritization cannot approve gates, hide failures or mutate source data."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from cloudguard.findings import SEVERITIES, STATUSES, build_report, finding, serialize
from cloudguard.risk import (MODEL_PATH, RiskInputError, assess_risk, load_model,
                             risk_category, validate_input, validate_model)
from cloudguard.exceptions import REVIEWED

try:
    import jsonschema  # Already supplied by the existing Checkov installation.
except ImportError:
    jsonschema = None


def item(severity="LOW", status="failed", exception=False, **values):
    return {**finding("checkov", "NEUTRAL", "aws_s3_bucket.example", status,
                     severity, "Synthetic risk test", exception=exception), **values}


def normalized(*items):
    return {"schema_version": "1.0", "generated_by": "cloudguard-ai",
            "sources": sorted({f["source"] for f in items}) or ["checkov"],
            "summary": {"total": len(items),
                **{s.lower(): sum(f["severity"] == s for f in items) for s in SEVERITIES},
                **{s: sum(f["status"] == s for f in items) for s in STATUSES}},
            "findings": list(items)}


def assess_one(**values):
    return assess_risk(normalized(item(**values)))["findings"][0]["risk"]


class RiskTests(unittest.TestCase):
    def test_empty_report_is_none_but_never_a_gate_pass(self):
        report = assess_risk(normalized())
        self.assertEqual(report["overall"], {"score": 0, "category": "NONE", "requires_review": False})
        self.assertEqual(report["summary"]["total"], 0)
        self.assertTrue(report["informational_only"])
        self.assertEqual(report["gate_decision"], "NOT_EVALUATED")
        self.assertNotIn("result", report)

    def test_all_severity_weights(self):
        for level, score, category in (("INFO", 10, "LOW"), ("LOW", 25, "LOW"),
                                      ("MEDIUM", 50, "MEDIUM"), ("HIGH", 75, "HIGH"),
                                      ("CRITICAL", 95, "CRITICAL")):
            with self.subTest(level=level):
                risk = assess_one(severity=level)
                self.assertEqual((risk["score"], risk["category"]), (score, category))
                self.assertTrue(risk["severity_known"])

    def test_unknown_severity_is_explicit_provisional_priority(self):
        output = assess_risk(normalized(item("UNKNOWN")))
        entry = output["findings"][0]
        self.assertEqual(entry["severity"], "UNKNOWN")
        self.assertEqual(entry["risk"]["score"], 50)
        self.assertFalse(entry["risk"]["severity_known"])
        self.assertTrue(entry["risk"]["requires_review"])
        self.assertIn("not inferred severity", entry["risk"]["factors"][0]["reason"])
        self.assertEqual(output["summary"]["unknown_severity"], 1)

    def test_threshold_boundaries(self):
        model = load_model()
        for score, expected in ((0, "NONE"), (1, "LOW"), (29, "LOW"), (30, "MEDIUM"),
                                (59, "MEDIUM"), (60, "HIGH"), (84, "HIGH"), (85, "CRITICAL"), (100, "CRITICAL")):
            self.assertEqual(risk_category(score, model), expected)

    def test_status_weights_round_up_using_integer_arithmetic(self):
        for status, approved, expected, state in (
                ("failed", False, 75, "failed"), ("warning", False, 38, "warning"),
                ("skipped", True, 19, "approved_exception"),
                ("skipped", False, 75, "unapproved_skip"), ("passed", False, 0, "passed")):
            risk = assess_one(severity="HIGH", status=status, exception=approved)
            self.assertEqual((risk["score"], risk["status_class"]), (expected, state))
            self.assertEqual(risk["exception_applied"], approved)

    def test_approved_exception_remains_visible_and_is_not_passed(self):
        output = assess_risk(normalized(item("HIGH", "skipped", True)))
        entry = output["findings"][0]
        self.assertEqual(entry["status"], "skipped")
        self.assertTrue(entry["exception"])
        self.assertGreater(entry["risk"]["score"], 0)
        self.assertEqual(output["summary"]["approved_exceptions"], 1)
        self.assertEqual(output["summary"]["passed"], 0)

    def test_all_six_approved_unknown_skips_have_provisional_review_priority(self):
        source = normalized(*(item("UNKNOWN", "skipped", True, control_id=rule, resource=resource)
                              for rule, resource in sorted(REVIEWED)))
        output = assess_risk(source)
        self.assertEqual(output["overall"], {"score": 13, "category": "LOW", "requires_review": True})
        self.assertEqual(output["summary"]["approved_exceptions"], 6)
        self.assertEqual(output["summary"]["unknown_severity"], 6)
        self.assertEqual(output["summary"]["failed"], 0)

    def test_unapproved_skip_is_never_promoted_or_discounted(self):
        entry = assess_risk(normalized(item("HIGH", "skipped", False)))["findings"][0]
        self.assertFalse(entry["exception"])
        self.assertEqual(entry["risk"]["score"], 75)
        self.assertTrue(entry["risk"]["requires_review"])

    def test_failed_finding_with_exception_flag_gets_no_discount(self):
        output = assess_risk(normalized(item("HIGH", "failed", True)))
        risk = output["findings"][0]["risk"]
        self.assertEqual(risk["score"], 75)
        self.assertTrue(risk["exception_conflict"])
        self.assertFalse(risk["exception_applied"])
        self.assertTrue(risk["requires_review"])
        self.assertEqual(output["summary"]["failed"], 1)
        self.assertEqual(output["summary"]["approved_exceptions"], 0)

    def test_unknown_status_is_preserved_and_needs_review(self):
        for status in ("unexpected", "FAILED", "pass"):
            source = normalized(item("LOW", status, True))
            output = assess_risk(source)
            entry = output["findings"][0]
            self.assertEqual(entry["status"], status)
            self.assertEqual(entry["risk"]["score"], 50)
            self.assertEqual(entry["risk"]["status_class"], "unknown")
            self.assertFalse(entry["risk"]["exception_applied"])
            self.assertEqual(output["summary"]["unknown_status"], 1)

    def test_passed_control_has_zero_priority_without_erasing_unknowns(self):
        output = assess_risk(normalized(item("UNKNOWN", "passed")))
        self.assertEqual(output["overall"]["score"], 0)
        self.assertFalse(output["overall"]["requires_review"])
        self.assertEqual(output["summary"]["unknown_severity"], 1)
        self.assertEqual(output["summary"]["passed"], 1)

    def test_one_critical_cannot_be_hidden_by_many_low_findings(self):
        output = assess_risk(normalized(item("CRITICAL"), *(item("LOW") for _ in range(1000))))
        self.assertEqual(output["overall"]["score"], 95)
        self.assertEqual(output["overall"]["category"], "CRITICAL")
        self.assertEqual(output["summary"]["low"], 1000)
        self.assertEqual(output["summary"]["critical"], 1)

    def test_multiple_findings_summary_categories_and_status_counts(self):
        source = normalized(item("CRITICAL"), item("LOW"), item("HIGH", "warning"),
                            item("HIGH", "skipped", True), item("LOW", "passed"), item("UNKNOWN", "future"))
        result = assess_risk(source)
        summary = result["summary"]
        self.assertEqual(summary["total"], 6)
        self.assertEqual(sum(summary[c] for c in ("none", "low", "medium", "high", "critical")), 6)
        self.assertEqual(sum(summary[c] for c in ("failed", "warning", "approved_exceptions", "unapproved_skips", "passed", "unknown_status")), 6)

    def test_exact_source_control_adjustments(self):
        cases = [("conftest", "SSH", 60), ("conftest", "S3_PUBLIC", 60),
                 ("conftest", "IAM", 60), ("conftest", "S3_ENCRYPTION", 55),
                 ("checkov", "CKV_AWS_24", 60), ("checkov", "CKV_AWS_25", 60),
                 ("checkov", "CKV_AWS_277", 60), ("checkov", "SSH", 50),
                 ("conftest", "SSH_extra", 50), ("conftest", None, 50)]
        for source, control, expected in cases:
            risk = assess_one(severity="UNKNOWN", source=source, control_id=control)
            self.assertEqual(risk["score"], expected)

    def test_resources_messages_and_metadata_do_not_invent_cloud_context(self):
        a = assess_one()
        b = assess_one(resource="aws_security_group.internet_exposed", message="public root wildcard critical",
                       metadata={"internet_exposed": True, "severity": "CRITICAL"})
        self.assertEqual(a, b)

    def test_adjustment_is_bounded_before_status_discount(self):
        output = assess_risk(normalized(item("CRITICAL", "skipped", True, control_id="CKV_AWS_24")))
        risk = output["findings"][0]["risk"]
        self.assertEqual(risk["score"], 25)
        self.assertEqual([f["value"] for f in risk["factors"]], [95, 10, 100, 25, 25])

    def test_factors_explain_calculation(self):
        risk = assess_one(severity="HIGH", status="warning")
        self.assertEqual([f["name"] for f in risk["factors"]], ["base_severity", "control_adjustment",
                         "bounded_base", "status_multiplier", "status_floor"])
        self.assertEqual(risk["factors"][-1]["value"], risk["score"])
        self.assertTrue(all(f["reason"] for f in risk["factors"]))

    def test_finding_identity_and_metadata_preserved_without_aliasing(self):
        original = item("HIGH", file="/main.tf", line=10, line_end=20,
                        metadata={"namespace": "main", "nested": {"values": [1, 2]}}, message="Private source message")
        source, model = normalized(original), load_model()
        before_source, before_model = deepcopy(source), deepcopy(model)
        output = assess_risk(source, model)
        recovered = {k: v for k, v in output["findings"][0].items() if k != "risk"}
        self.assertEqual(recovered, original)
        self.assertEqual(source, before_source)
        self.assertEqual(model, before_model)
        output["findings"][0]["metadata"]["nested"]["values"].append(3)
        self.assertEqual(source, before_source)

    def test_same_data_and_reordered_records_produce_identical_bytes(self):
        source = normalized(item("HIGH"), item("LOW"), item("HIGH"))
        model = load_model()
        a = serialize(assess_risk(source, model))
        source["findings"].reverse()
        model["control_adjustments"].reverse()
        self.assertEqual(a, serialize(assess_risk(source, model)))
        self.assertEqual(assess_risk(source)["summary"]["total"], 3)
        self.assertNotIn("timestamp", a)

    def test_model_digest_changes_when_effective_configuration_changes(self):
        model = load_model()
        a = assess_risk(normalized(item("LOW")), model)
        model["severity_weights"]["LOW"] = 26
        b = assess_risk(normalized(item("LOW")), model)
        self.assertNotEqual(a["risk_model_sha256"], b["risk_model_sha256"])
        self.assertEqual(b["overall"]["score"], 26)

    def test_low_or_zero_risk_cannot_convert_a_failed_gate_to_pass(self):
        model = load_model()
        model["severity_weights"]["INFO"] = model["severity_weights"]["LOW"] = 0
        result = assess_risk(normalized(item("LOW")), model)
        self.assertEqual(result["overall"]["category"], "NONE")
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertEqual(result["findings"][0]["status"], "failed")
        self.assertEqual(result["gate_decision"], "NOT_EVALUATED")
        self.assertTrue(result["informational_only"])
        self.assertNotIn("result", result)

    def test_engine_uses_neither_network_nor_subprocesses(self):
        with patch("socket.socket", side_effect=AssertionError("Network call")), \
                patch("subprocess.run", side_effect=AssertionError("Subprocess call")):
            self.assertEqual(assess_risk(normalized(item()))["overall"]["score"], 25)


class RiskValidationTests(unittest.TestCase):
    def test_malformed_normalized_reports(self):
        broken = [None, [], {}, {"schema_version": "1.0"}]
        for path, value in (("findings", {}), ("summary", {}), ("generated_by", "other"),
                            ("sources", []), ("sources", ["checkov", "checkov"]), ("sources", ["future"])):
            raw = normalized(item()); raw[path] = value; broken.append(raw)
        for field, value in (("severity", "urgent"), ("status", None), ("status", " "),
                             ("line", True), ("line_end", 1), ("exception", "true"),
                             ("metadata", []), ("resource", {}), ("source", "future")):
            raw = normalized(item()); raw["findings"][0][field] = value; broken.append(raw)
        raw = normalized(item()); raw["summary"]["failed"] = 0; broken.append(raw)
        raw = normalized(item()); raw["summary"]["total"] = True; broken.append(raw)
        raw = normalized(item()); raw["findings"][0].pop("message"); broken.append(raw)
        raw = normalized(item()); raw["findings"][0]["metadata"] = {1: "bad"}; broken.append(raw)
        raw = normalized(item()); raw["findings"][0]["metadata"] = {"bad": float('nan')}; broken.append(raw)
        for raw in broken:
            with self.subTest(raw=raw), self.assertRaises(RiskInputError):
                assess_risk(raw)

    def test_unsupported_versions_are_rejected(self):
        for version in (None, 1, "2.0"):
            raw = normalized(item()); raw["schema_version"] = version
            with self.assertRaisesRegex(RiskInputError, "schema version"):
                assess_risk(raw)
        raw = normalized(item()); raw["findings"][0]["schema_version"] = "2.0"
        with self.assertRaises(RiskInputError):
            assess_risk(raw)

    def test_invalid_models_and_ambiguous_mappings_are_rejected(self):
        broken = [None, {}, []]
        for field, value in (("risk_model_version", "2.0"), ("unknown_status_floor", 0),
                             ("control_adjustments", {})):
            model = load_model(); model[field] = value; broken.append(model)
        model = load_model(); model["severity_weights"]["LOW"] = True; broken.append(model)
        model = load_model(); model["severity_weights"]["LOW"] = 101; broken.append(model)
        model = load_model(); model["severity_weights"]["LOW"] = 80; broken.append(model)
        model = load_model(); model["category_minimums"]["MEDIUM"] = 1; broken.append(model)
        for state, ratio in (("failed", [0, 1]), ("warning", [1, 0]), ("passed", [1, 1]),
                             ("approved_exception", [0, 1]), ("unknown", [1, 2])):
            model = load_model(); model["status_multipliers"][state] = ratio; broken.append(model)
        model = load_model(); model["control_adjustments"].append(model["control_adjustments"][0]); broken.append(model)
        model = load_model(); model["control_adjustments"][0]["value"] = -10; broken.append(model)
        for model in broken:
            with self.subTest(model=model), self.assertRaises(RiskInputError):
                validate_model(model)

    def test_current_phase31_fixture_report_is_consumed_without_changes(self):
        inputs = [(source, json.loads((ROOT / f"tests/fixtures/normalization/{source}.json").read_text()))
                  for source in ("checkov", "conftest")]
        normalized_report = build_report(inputs)
        original = deepcopy(normalized_report)
        result = assess_risk(normalized_report)
        self.assertEqual(normalized_report, original)
        self.assertEqual(result["overall"]["score"], 75)
        self.assertEqual(result["summary"]["total"], 3)


class RiskCliTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts/score-risk.py"), *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT)

    def test_help_and_required_input(self):
        self.assertEqual(self.cli("--help").returncode, 0)
        self.assertEqual(self.cli().returncode, 2)

    def test_cli_success_private_text_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "in.json", Path(directory) / "out.json"
            payload = serialize(normalized(item("CRITICAL", message="NEVER_ECHO_SECRET", metadata={"private": "NEVER_ECHO_SECRET"})))
            source.write_text(payload)
            result = self.cli("--input", source, "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("NEVER_ECHO_SECRET", result.stdout + result.stderr)
            self.assertEqual(source.read_text(), payload)
            report = json.loads(output.read_text())
            self.assertEqual(report["overall"]["category"], "CRITICAL")
            self.assertEqual(report["gate_decision"], "NOT_EVALUATED")
            self.assertEqual(report["findings"][0]["message"], "NEVER_ECHO_SECRET")

    def test_no_overwrite_even_when_output_is_input_or_model(self):
        with tempfile.TemporaryDirectory() as directory:
            source, model, output = (Path(directory) / n for n in ("input.json", "model.json", "out.json"))
            source.write_text(serialize(normalized(item())))
            model.write_text(MODEL_PATH.read_text())
            output.write_text("EXISTING_CONTENT")
            for destination in (source, model, output):
                before = destination.read_bytes()
                result = self.cli("--input", source, "--model", model, "--output", destination)
                self.assertEqual(result.returncode, 2)
                self.assertIn("already exists", result.stderr)
                self.assertEqual(destination.read_bytes(), before)

    def test_bad_json_duplicate_keys_and_invalid_versions_leave_no_output(self):
        values = ['{"private": "NEVER_ECHO_SECRET",', '{"schema_version":"1.0","schema_version":"2.0"}',
                  '{"x":NaN}', '{}', '[]', '{"schema_version":"9.0"}']
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "in.json", Path(directory) / "out.json"
            for value in values:
                source.write_text(value)
                result = self.cli("--input", source, "--output", output)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())
                self.assertNotIn("NEVER_ECHO_SECRET", result.stdout + result.stderr)
            self.assertEqual(self.cli("--input", source.with_name("missing"), "--output", output).returncode, 2)

    def test_cli_deterministic_output_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source, a, b = (Path(directory) / name for name in ("input.json", "a.json", "b.json"))
            source.write_text(serialize(normalized(item("CRITICAL"), item("LOW"))))
            for output in (a, b):
                self.assertEqual(self.cli("--input", source, "--output", output).returncode, 0)
            self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_cli_invalid_model_leaves_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            source, model, output = (Path(directory) / name for name in ("input.json", "model.json", "out.json"))
            source.write_text(serialize(normalized(item())))
            model.write_text('{}')
            result = self.cli("--input", source, "--model", model, "--output", output)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


@unittest.skipIf(jsonschema is None, "JSON Schema tests require jsonschema from the existing Checkov toolchain")
class RiskSchemaTests(unittest.TestCase):
    def setUp(self):
        schema = json.loads((ROOT / "security/risk-report.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        self.validator = jsonschema.Draft202012Validator(schema)

    def test_generated_reports_validate_against_schema(self):
        for source in (normalized(), normalized(item("CRITICAL")), normalized(item("UNKNOWN", "skipped", True)),
                       normalized(item("HIGH", "passed")), normalized(item("LOW", "future"))):
            self.validator.validate(assess_risk(source))

    def test_schema_rejects_gate_claims_out_of_range_and_missing_identity(self):
        original = assess_risk(normalized(item()))
        for mutation in ("gate", "bounds", "identity", "exception"):
            report = deepcopy(original)
            if mutation == "gate": report["gate_decision"] = "PASS"
            if mutation == "bounds": report["overall"]["score"] = 101
            if mutation == "identity": report["findings"][0].pop("control_id")
            if mutation == "exception": report["findings"][0]["exception"] = "true"
            with self.assertRaises(jsonschema.ValidationError):
                self.validator.validate(report)
