"""Validation failures remain fatal and never publish arbitrary Terraform text."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from cloudguard import quality


class ValidationDiagnosticsTests(unittest.TestCase):
    def test_checksum_diagnostic_is_exact(self):
        result = quality.validation_diagnostics(json.dumps({"diagnostics": [
            {"summary": quality.CHECKSUM_ERROR, "detail": ""}]}))
        self.assertEqual(result[0], "Error: " + quality.CHECKSUM_ERROR)

    def test_values_and_workflow_commands_are_never_printed(self):
        for summary in ("Unsupported argument", "secret=NEVER_EXPORT", "::error::NEVER_EXPORT"):
            output = quality.validation_diagnostics(json.dumps({"diagnostics": [{
                "summary": summary, "detail": "NEVER_EXPORT", "snippet": {"code": "NEVER_EXPORT"},
                "range": {"filename": "NEVER_EXPORT"}, "expression": "NEVER_EXPORT"}]}))
            self.assertNotIn("NEVER_EXPORT", " ".join(output))
        self.assertNotIn("NEVER_EXPORT", " ".join(quality.validation_diagnostics("NEVER_EXPORT")))

    def test_both_failed_roots_are_reported_and_fail_quality(self):
        def fake_run(args, **kwargs):
            failed = "validate" in args
            if failed:
                self.assertIn("-json", args)
                json.dump({"diagnostics": [{"summary": quality.CHECKSUM_ERROR}]}, kwargs["stdout"])
            return SimpleNamespace(returncode=1 if failed else 0)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(quality, "PRIVATE", Path(directory)), \
                patch.object(quality, "tool", side_effect=lambda name: [name]), \
                patch.object(quality, "run", side_effect=fake_run), \
                patch.object(quality, "record"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertFalse(quality.quality())
        for root in ("terraform", "bootstrap/aws-plan-role"):
            self.assertIn(root + "-validate: Error: " + quality.CHECKSUM_ERROR, output.getvalue())
            self.assertIn(root + "-validate: FAIL", output.getvalue())
