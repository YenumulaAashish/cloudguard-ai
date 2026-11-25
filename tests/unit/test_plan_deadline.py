"""Expiry bounds Terraform subprocesses; no Terraform or AWS commands executed."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import planning
class PlanDeadlineTests(unittest.TestCase):
    def test_expired_deadline_prevents_any_subprocess(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'terraform').mkdir()
            with patch.object(planning,'ROOT',root),patch.object(planning,'PRIVATE',root/'private'),patch.object(planning,'record'),patch.object(planning,'tool',return_value=['terraform']),patch.object(planning,'run') as run,patch.object(planning.time,'time',return_value=100):
                self.assertFalse(planning.create_plan(deadline=100));run.assert_not_called()
    def test_all_terraform_subprocesses_have_expiry_timeout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'terraform').mkdir();calls=[]
            def fake(args,**kwargs):
                calls.append(kwargs['timeout'])
                if 'show' in args:json.dump({'format_version':'1.2','terraform_version':'1.9.8','planned_values':{'root_module':{}},'resource_changes':[]},kwargs['stdout'])
                return SimpleNamespace(returncode=0)
            with patch.object(planning,'ROOT',root),patch.object(planning,'PRIVATE',root/'private'),patch.object(planning,'record'),patch.object(planning,'tool',return_value=['terraform']),patch.object(planning,'run',side_effect=fake),patch.object(planning.time,'time',side_effect=[100,110,120,130]):
                self.assertTrue(planning.create_plan(deadline=160))
            self.assertEqual(calls,[60,50,40,30])
    def test_timeout_is_failure_without_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'terraform').mkdir()
            with patch.object(planning,'ROOT',root),patch.object(planning,'PRIVATE',root/'private'),patch.object(planning,'record'),patch.object(planning,'tool',return_value=['terraform']),patch.object(planning,'run',side_effect=planning.subprocess.TimeoutExpired('terraform',1)) as run,patch.object(planning.time,'time',return_value=100):
                self.assertFalse(planning.create_plan(deadline=160));self.assertEqual(run.call_count,1)
