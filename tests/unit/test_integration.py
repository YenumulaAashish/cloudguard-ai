"""Full-chain integrity and transactional failure cases; no live services."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from cloudguard import integration as cg
from cloudguard.exceptions import REVIEWED
from cloudguard.findings import serialize
from cloudguard.risk import load_model


def baseline():
    return [('checkov', {'check_type': 'terraform',
        'summary': {'passed': 0, 'failed': 0, 'skipped': 6, 'parsing_errors': 0},
        'results': {'passed_checks': [], 'failed_checks': [], 'parsing_errors': [],
                    'skipped_checks': [{'check_id': rule, 'resource': resource,
                                        'check_result': {'result': 'SKIPPED'}}
                                       for rule, resource in sorted(REVIEWED)]}})]


def gates(state='PASS'):
    return {'checkov': state, 'exception_contract': state, 'policy_tests': state, 'opa_conftest': 'UNKNOWN'}


class ChainTests(unittest.TestCase):
    def test_complete_baseline_and_receipt(self):
        with patch.object(cg, 'current_policy', return_value=gates()):
            chain, private, public = cg.prepare(baseline(), evidence=True)
        summary = chain['summary']
        self.assertEqual(summary['findings'], {'total': 6, 'failed': 0, 'approved_exceptions': 6})
        self.assertEqual(summary['risk'], {'score': 13, 'category': 'LOW', 'requires_review': True})
        self.assertEqual(summary['advisory'], {'mode': 'offline', 'findings_reviewed': 6})
        self.assertEqual(summary['policy'], gates())
        self.assertEqual(set(private), set(cg.PRIVATE_NAMES))
        self.assertEqual(set(public), set(cg.PUBLIC_NAMES))
        receipt = json.loads(public['phase3-evidence.json'])
        self.assertEqual(receipt['completion'], 'COMPLETE')
        self.assertTrue(receipt['informational_only'])
        self.assertNotIn('policy', receipt)

    def test_complete_chain_reproduction_and_source_immutability(self):
        raw = baseline(); original = deepcopy(raw)
        first = cg.prepare(raw); second = cg.prepare(raw)
        self.assertEqual(first, second); self.assertEqual(raw, original)
        for values in first[1:]:
            self.assertTrue(all(text.endswith('\n') for text in values.values()))

    def test_low_risk_with_policy_fail_and_unknown(self):
        for state in ('FAIL', 'UNKNOWN'):
            with patch.object(cg, 'current_policy', return_value=gates(state)):
                chain, _, public = cg.prepare(baseline(), evidence=True)
            self.assertEqual(chain['summary']['policy'], gates(state))
            self.assertEqual(chain['summary']['risk']['score'], 13)
            self.assertEqual(json.loads(public['phase3-evidence.json'])['completion'], 'COMPLETE')

    def test_missing_evidence_never_implies_pass(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(cg, 'REPORTS', Path(folder)), \
             patch('cloudguard.pr_evidence.REPORTS', Path(folder)):
            # Explicitly point adapter at empty records; default reporting also needs no evidence.
            from cloudguard.pr_evidence import current_policy
            with patch.object(cg, 'current_policy', side_effect=lambda n: current_policy(n, Path(folder), Path(folder))):
                summary = cg.prepare(baseline(), evidence=True)[0]['summary']
        self.assertEqual(set(summary['policy'].values()), {'UNKNOWN'})

    def test_failed_findings_survive_whole_chain(self):
        raw = baseline(); record = raw[0][1]
        record['results']['failed_checks'] = [{'check_id': 'NEUTRAL', 'resource': 'private.resource',
                                             'severity': 'CRITICAL', 'check_result': {'result': 'FAILED'}}]
        record['summary']['failed'] = 1
        summary = cg.prepare(raw)[0]['summary']
        self.assertEqual(summary['findings']['failed'], 1)
        self.assertEqual(summary['risk']['category'], 'CRITICAL')
        self.assertEqual(summary['findings']['approved_exceptions'], 6)

    def test_malformed_raw_checkov_and_conftest(self):
        for source in ('checkov', 'conftest'):
            for bad in (None, {}, [], {'results': 'bad'}):
                with self.subTest(source=source, bad=bad), self.assertRaises(ValueError):
                    cg.prepare([(source, bad)])

    def test_mixed_checkov_conftest_and_empty_conftest(self):
        for failures in ([], [{'msg': 'SSH: aws_security_group.example exposes SSH to the world'}]):
            raw = baseline() + [('conftest', [{'filename': 'input.json', 'namespace': 'main',
                                             'successes': 1, 'failures': failures}])]
            result = cg.prepare(raw)[0]['summary']
            self.assertEqual(result['findings']['failed'], len(failures))
            self.assertEqual(result['policy']['opa_conftest'], 'UNKNOWN')

    def test_every_intermediate_schema_and_version_failure(self):
        inputs = baseline(); chain = cg.prepare(inputs)[0]; model = load_model()
        for name in chain:
            for corrupt in ({}, {**chain[name], 'schema_version': '999'}, {**chain[name], 'private': 'leak'}):
                changed = deepcopy(chain); changed[name] = corrupt
                with self.subTest(name=name), self.assertRaises(ValueError):
                    cg.validate_chain(inputs, changed, chain['summary']['policy'], model)

    def test_unrelated_normalized_risk_advisory_and_summary_rejected(self):
        inputs = baseline(); chain = cg.prepare(inputs)[0]
        for name, mutation in [
            ('normalized', lambda x: x['findings'][0].update(resource='unrelated')),
            ('risk', lambda x: x['findings'][0]['risk'].update(score=0)),
            ('advisory', lambda x: x['findings'][0].update(resource='unrelated')),
            ('summary', lambda x: x['risk'].update(score=0)),
            ('summary', lambda x: x['policy'].update(checkov='PASS'))]:
            changed = deepcopy(chain); mutation(changed[name])
            with self.subTest(name=name), self.assertRaises(ValueError):
                cg.validate_chain(inputs, changed, chain['summary']['policy'], load_model())

    def test_invalid_exception_state_and_authority_fields_rejected(self):
        raw = baseline(); chain = cg.prepare(raw)[0]
        for name, mutate in [
            ('normalized', lambda x: x['findings'][0].update(exception=False)),
            ('risk', lambda x: x.update(gate_decision='PASS')),
            ('advisory', lambda x: x.update(informational_only=False)),
            ('advisory', lambda x: x['findings'][0]['risk'].update(requires_review=False)),
            ('summary', lambda x: x.update(informational_only=False))]:
            changed = deepcopy(chain); mutate(changed[name])
            with self.assertRaises(ValueError): cg.validate_chain(raw, changed, chain['summary']['policy'], load_model())

    def test_missing_intermediate_rejected(self):
        raw = baseline(); chain = cg.prepare(raw)[0]
        for name in chain:
            changed = deepcopy(chain); del changed[name]
            with self.assertRaises(ValueError): cg.validate_chain(raw, changed, chain['summary']['policy'], load_model())

    def test_stale_run_fingerprint_and_unrelated_evidence(self):
        from cloudguard.pr_evidence import current_policy
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder); raw = baseline()
            def save(name, obj): (directory / (name + '.json')).write_text(serialize(obj))
            save('checkov-raw', raw[0][1])
            for field in ('run_id', 'source_digest'):
                context = {'run_id': 'same-run', 'source_digest': 'same-source'}
                save('run-context', context)
                save('checkov', {**context, field: 'stale', 'result': 'PASS'})
                with patch('cloudguard.pr_evidence.fingerprint', return_value='same-source'), \
                     patch.object(cg, 'current_policy', side_effect=lambda n: current_policy(n, directory, directory)):
                    self.assertEqual(cg.prepare(raw, evidence=True)[0]['summary']['policy']['checkov'], 'UNKNOWN')
            save('checkov', {**context, 'result': 'PASS'})
            other = deepcopy(raw[0][1]); other['results']['skipped_checks'][0]['resource'] = 'unrelated'
            save('checkov-raw', other)
            with patch('cloudguard.pr_evidence.fingerprint', return_value='same-source'), \
                 patch.object(cg, 'current_policy', side_effect=lambda n: current_policy(n, directory, directory)):
                self.assertEqual(cg.prepare(raw, evidence=True)[0]['summary']['policy']['checkov'], 'UNKNOWN')

    def test_evidence_changes_during_run_fail_closed(self):
        with patch.object(cg, 'evidence_snapshot', side_effect=[('before',), ('after',)]):
            with self.assertRaises(cg.IntegrationError): cg.prepare(baseline(), evidence=True)

    def test_provider_failure_stops_chain(self):
        with patch('cloudguard.advice.OfflineProvider.analyze', side_effect=RuntimeError('SECRET')):
            with self.assertRaises(ValueError): cg.prepare(baseline())

    def test_nondeterministic_advice_is_rejected(self):
        original = cg.analyze_security; calls = []
        def vary(*args, **kwargs):
            report = original(*args, **kwargs); calls.append(1)
            report['findings'][0]['analysis']['summary'] = 'Advice variant ' + str(len(calls))
            return report
        with patch.object(cg, 'analyze_security', side_effect=vary):
            with self.assertRaises(cg.IntegrationError): cg.prepare(baseline())

    def test_secret_and_injection_data_stay_private(self):
        secrets = ['AKIA' + 'Q' * 16, 'AWS_SECRET_ACCESS_KEY=synthetic-secret', 'ghp_synthetic-token',
                   'api_key=synthetic', 'Bearer synthetic-token', '-----BEGIN PRIVATE KEY-----',
                   r'C:\private\source.tf', '/private/source.tf', 'resource "aws_vpc" "private" {}',
                   'planned_values private-plan', '# Fake heading', '<script>evil</script>',
                   '<!-- cloudguard-ai-security-review -->', '[link](javascript:evil)']
        raw = baseline(); sentinel = '\n'.join(secrets)
        for row in raw[0][1]['results']['skipped_checks']:
            row.update(check_name=sentinel, file_path=sentinel, resource=sentinel, metadata={'private': sentinel})
        _, private, public = cg.prepare(raw)
        self.assertIn('synthetic', private['normalized.json'])
        for token in secrets:
            self.assertNotIn(token, public['pr-summary.json'])
            self.assertNotIn(token, public['phase3-evidence.json'])
        self.assertEqual(public['pr-summary.md'].count('<!-- cloudguard-ai-security-review -->'), 1)
        self.assertNotIn('synthetic', public['pr-summary.md'])

    def test_large_chain_keeps_public_outputs_bounded(self):
        raw = baseline(); raw[0][1]['results']['skipped_checks'] *= 60; raw[0][1]['summary']['skipped'] = 360
        chain, _, public = cg.prepare(raw)
        self.assertEqual(chain['summary']['findings']['total'], 360)
        self.assertTrue(all(len(s.encode()) <= 4096 for s in public.values()))

    def test_no_network_aws_ai_or_subprocess_calls(self):
        with patch('socket.socket', side_effect=AssertionError('network')), \
             patch('subprocess.run', side_effect=AssertionError('execution')), \
             patch.dict('os.environ', {}, clear=True):
            cg.prepare(baseline())

    def test_remote_schema_reference_never_fetched(self):
        with patch.object(cg, 'read_document', return_value={'$ref': 'https://invalid.example/schema'}), \
             patch('socket.socket', side_effect=AssertionError('network')):
            with self.assertRaises(cg.IntegrationError): cg.schema_validate({}, 'summary')

    def test_manifest_closed_schema_no_false_gate_claims(self):
        receipt = json.loads(cg.prepare(baseline())[2]['phase3-evidence.json'])
        for mutate in [lambda x: x.update(secret='private'), lambda x: x.update(informational_only=False),
                       lambda x: x['validation'].update(byte_reproduction='UNKNOWN'),
                       lambda x: x['components'].update(deployment='PASS')]:
            changed = deepcopy(receipt); mutate(changed)
            with self.assertRaises(cg.IntegrationError): cg.schema_validate(changed, 'manifest')


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / 'reports/private/run'
        self.public = self.root / 'reports/sanitized/run'

    def run_chain(self, **kwargs):
        return cg.publish(baseline(), self.private, self.public, root=self.root, **kwargs)

    def test_complete_publication_and_exact_file_sets(self):
        result = self.run_chain()
        self.assertEqual(result['risk']['score'], 13)
        self.assertEqual({p.name for p in self.private.iterdir()}, set(cg.PRIVATE_NAMES))
        self.assertEqual({p.name for p in self.public.iterdir()}, set(cg.PUBLIC_NAMES))

    def test_collision_preserves_all_existing_files(self):
        self.run_chain(); before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with self.assertRaises(ValueError): self.run_chain()
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_existing_empty_directory_also_collision(self):
        self.public.mkdir(parents=True)
        with self.assertRaises(ValueError): self.run_chain()
        self.assertFalse(self.private.exists()); self.assertTrue(self.public.exists())

    def test_wrong_privacy_boundaries_rejected_before_write(self):
        for private, public in [(self.public, self.private), (self.root/'outside', self.public),
                                (self.private, self.root/'reports/sanitized'), (self.private, self.private/'public')]:
            with self.assertRaises(ValueError): cg.publish(baseline(), private, public, root=self.root)
        self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())

    def test_stage_failure_never_creates_output_directories(self):
        with patch.object(cg, 'analyze_security', side_effect=ValueError('failure')):
            with self.assertRaises(ValueError): self.run_chain()
        self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())

    def test_write_failure_rolls_back_owned_files_and_directories(self):
        original = cg.write_file
        for fail_at in (1, 3, 5, 7):
            calls = []
            def broken(path, text):
                calls.append(path)
                original(path, text)
                if len(calls) == fail_at: raise OSError('synthetic write failure')
            with patch.object(cg, 'write_file', side_effect=broken):
                with self.assertRaises(OSError): self.run_chain()
            self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())

    def test_readback_missing_intermediate_rolls_back(self):
        original = cg.read_document
        def missing(path, *args):
            if Path(path) == self.private/'risk.json': raise ValueError('missing')
            return original(path, *args)
        with patch.object(cg, 'read_document', side_effect=missing):
            with self.assertRaises(ValueError): self.run_chain()
        self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())

    def test_readback_tampered_summary_rolls_back(self):
        original = cg.write_file
        def tamper(path, text):
            if path.name == 'pr-summary.json':
                obj = json.loads(text); obj['risk']['score'] = 0; text = serialize(obj)
            original(path, text)
        with patch.object(cg, 'write_file', side_effect=tamper):
            with self.assertRaises(ValueError): self.run_chain()
        self.assertFalse(self.public.exists())

    def test_completion_manifest_is_last_and_fully_written(self):
        original = cg.write_file; order = []
        def observe(path, text):
            self.assertFalse((self.public/'phase3-evidence.json').exists())
            order.append(path.name); original(path, text)
        with patch.object(cg, 'write_file', side_effect=observe): self.run_chain()
        self.assertEqual(order[-1], '.phase3-evidence.tmp')
        cg.schema_validate(json.loads((self.public/'phase3-evidence.json').read_text()), 'manifest')

    def test_rename_failure_leaves_no_completed_run(self):
        with patch.object(Path, 'rename', side_effect=OSError('rename failure')):
            with self.assertRaises(OSError): self.run_chain()
        self.assertFalse(self.private.exists()); self.assertFalse(self.public.exists())


class IntegrationCliTests(unittest.TestCase):
    def test_help_missing_input_and_no_ai_option(self):
        for args, code in [(['--help'], 0), ([], 2), (['--mode', 'ai'], 2)]:
            result = subprocess.run([sys.executable, str(ROOT/'scripts/run-phase3.py'), *args], capture_output=True)
            self.assertEqual(result.returncode, code)

    def test_cli_complete_chain_and_fixed_failure_diagnostics(self):
        spec = importlib.util.spec_from_file_location('phase3_cli', ROOT/'scripts/run-phase3.py')
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); raw = root/'input.json'; raw.write_text(serialize(baseline()[0][1]))
            def local_publish(*args, **kwargs): return cg.publish(*args, **kwargs, root=root)
            with patch.object(cli, 'ROOT', root), patch.object(cli, 'publish', side_effect=local_publish):
                self.assertEqual(cli.main(['--checkov', str(raw)]), 0)
                self.assertEqual(cli.main(['--checkov', str(raw)]), 2)
                raw.write_text('{"secret":"NEVER_ECHO",')
                import contextlib, io
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors): self.assertEqual(cli.main(['--checkov', str(raw)]), 2)
                self.assertNotIn('NEVER_ECHO', errors.getvalue()); self.assertNotIn(folder, errors.getvalue())


class IntegrationWorkflowTests(unittest.TestCase):
    def test_integrated_step_and_completion_gated_upload(self):
        import yaml
        flow = yaml.load((ROOT/'.github/workflows/terraform-ci.yml').read_text(), Loader=yaml.BaseLoader)
        steps = flow['jobs']['offline']['steps']
        step = next(s for s in steps if s.get('id') == 'phase3')
        self.assertEqual(step['if'], 'always()')
        self.assertEqual(step['run'].strip(), 'python scripts/run-phase3.py --checkov reports/private/checkov-raw.json --current-evidence --mode offline')
        upload = next(s for s in steps if s.get('with', {}).get('name', '').startswith('pr-summary-'))
        self.assertEqual(upload['if'], "always() && steps.phase3.outcome == 'success'")
        self.assertEqual(set(upload['with']['path'].split()), {'reports/sanitized/phase35/'+n for n in cg.PUBLIC_NAMES})
        self.assertEqual(flow['permissions'], {'contents': 'read'})
        self.assertNotIn('permissions', flow['jobs']['offline'])

    def test_guard_and_fork_protection_remain(self):
        from cloudguard.safety import inspect
        self.assertEqual(inspect(ROOT), [])
        text = (ROOT/'.github/workflows/terraform-plan.yml').read_text()
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', text)
        self.assertIn('environment: aws-plan', text)
        self.assertNotIn('pull_request_target', text)
