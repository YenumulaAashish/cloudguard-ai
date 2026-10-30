"""Exporter privacy tests; no private files or AWS access."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('exporter', HERE / 'export-reports.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
DEMO = json.loads((HERE.parent / 'src/data/demo.json').read_text())


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'reports/sanitized/example'
        self.folder.mkdir(parents=True)
        for key, name in [('pr', 'pr-summary'), ('phase3', 'phase3-evidence'),
                          ('posture', 'posture-summary'), ('phase4', 'phase4-completion')]:
            (self.folder / (name + '.json')).write_text(json.dumps(DEMO[key]))
        self.root_patch = patch.object(exporter, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_public_export_matches_snapshot(self):
        self.assertEqual(exporter.export(self.folder, self.folder), DEMO)

    def test_private_path_rejected_before_read(self):
        with self.assertRaises(ValueError):
            exporter.read_public(self.root / 'reports/private', 'pr-summary.json')

    def test_extra_private_fields_rejected(self):
        value = dict(DEMO['pr'], secret='PRIVATE_CANARY')
        (self.folder / 'pr-summary.json').write_text(json.dumps(value))
        with self.assertRaises(Exception):
            exporter.export(self.folder, self.folder)

    def test_duplicate_keys_rejected(self):
        (self.folder / 'pr-summary.json').write_text('{"x": 1, "x": 2}')
        with self.assertRaises(ValueError):
            exporter.read_public(self.folder, 'pr-summary.json')

    def test_missing_receipt_rejected(self):
        (self.folder / 'phase4-completion.json').unlink()
        with self.assertRaises(FileNotFoundError):
            exporter.export(self.folder, self.folder)

    def test_oversize_rejected(self):
        (self.folder / 'pr-summary.json').write_text(' ' * 4097)
        with self.assertRaises(ValueError):
            exporter.read_public(self.folder, 'pr-summary.json')

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            exporter.read_public(self.folder, '../../private/pr-summary.json')

    def test_real_plan_claim_rejected_for_offline_snapshot(self):
        value = json.loads(json.dumps(DEMO['pr']))
        value['policy']['opa_conftest'] = 'PASS'
        (self.folder / 'pr-summary.json').write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            exporter.export(self.folder, self.folder)


if __name__ == '__main__':
    unittest.main()
