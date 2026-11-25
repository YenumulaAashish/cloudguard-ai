"""Actual offline tools against generated source and a clearly synthetic plan fixture."""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
from ..runtime import ROOT,tool
from ..exceptions import terraform_report
from ..policy_reporting import failure_reasons

MANDATORY=('terraform_validate','checkov','opa','conftest','cost')

class ToolGates:
    def run(self,folder,*,native=False):
        folder=Path(folder);out={k:{'status':'NOT_RUN','reason':'TOOL_UNAVAILABLE'} for k in MANDATORY if k!='cost'}
        # Do not pass operator/AI/AWS credentials, proxies, profiles or endpoint overrides.
        env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        home=folder/'tool-home';home.mkdir(exist_ok=True,mode=0o700)
        env.update(HOME=str(home),USERPROFILE=str(home))
        env.update(CHECKPOINT_DISABLE='1',AWS_EC2_METADATA_DISABLED='true',TF_IN_AUTOMATION='true')
        mirror=ROOT/'terraform/.terraform/providers'
        (folder/'offline.tfrc').write_text('disable_checkpoint = true\nprovider_installation { filesystem_mirror { path = '+json.dumps(mirror.as_posix())+' include = ["registry.terraform.io/hashicorp/aws"] } }\n')
        env['TF_CLI_CONFIG_FILE']=str(folder/'offline.tfrc')
        def call(name,args,tag):
            with (folder/(tag+'.stderr')).open('w') as err:
                r=subprocess.run(tool(name)+args,env=env,capture_output=False,stdout=subprocess.PIPE,stderr=err,text=True,timeout=120,cwd=ROOT)
            (folder/(tag+'.stdout')).write_text(r.stdout);return r
        try:
            if native:
                validation=json.loads((folder/'validate.private.log').read_text(encoding='utf-8').strip())
                out['terraform_validate']={'status':'PASS' if validation.get('valid') is True else 'FAIL','reason':'NATIVE_PROVIDER_SCHEMA'}
            else:
                shutil.copyfile(ROOT/'terraform/.terraform.lock.hcl',folder/'.terraform.lock.hcl')
                init=call('terraform',['-chdir='+str(folder),'init','-backend=false','-input=false','-lockfile=readonly','-no-color'],'init')
                validation=call('terraform',['-chdir='+str(folder),'validate','-json'],'validate') if init.returncode==0 else None
                out['terraform_validate']={'status':'PASS' if validation and validation.returncode==0 else 'FAIL','reason':'OFFLINE_PROVIDER_SCHEMA'}
        except Exception:pass
        try:
            r=call('checkov',['-d',str(folder/'deletion-security-source' if native and (folder/'deletion-security-source').is_dir() else folder),'--config-file',str(ROOT/'.checkov.yml'),'--output','json'],'checkov')
            report=terraform_report(json.loads(r.stdout));s=report['summary']
            ok=r.returncode==0 and s['failed']==s['skipped']==s['parsing_errors']==0 and s['passed']>0
            out['checkov']={'status':'PASS' if ok else 'FAIL','reason':'GENERATED_SOURCE_NO_EXCEPTIONS','passed':s['passed'],'failed':s['failed'],'skipped':s['skipped'],'failure_reasons':[{'rule_id':rule,'reason_code':'SOURCE_CHECK_FAILED','count':1} for rule in sorted({x['check_id'] for x in report['results']['failed_checks'] if re.fullmatch(r'CKV2?_AWS_[0-9]{1,5}',x.get('check_id',''))})]}
        except (OSError,subprocess.TimeoutExpired):pass
        except Exception:out['checkov']={'status':'FAIL','reason':'GENERATED_SOURCE_NO_EXCEPTIONS'}
        try:
            r=call('opa',['eval','-f','json','-d',str(ROOT/'policies/terraform'),'-i',str(folder/('tfplan.json' if native else 'mock-plan.json')),'data.main.deny'],'opa')
            values=json.loads(r.stdout)['result'][0]['expressions'][0]['value']
            out['opa']={'status':'PASS' if r.returncode==0 and values==[] else 'FAIL','reason':'REAL_PLAN_POLICY' if native else 'SYNTHETIC_PLAN_POLICY'}
        except Exception:pass
        try:
            r=call('conftest',['test',str(folder/('tfplan.json' if native else 'mock-plan.json')),'--policy',str(ROOT/'policies/terraform'),'--output','json'],'conftest')
            rows=json.loads(r.stdout);fail=sum(len(x.get('failures',[])) for x in rows)
            exceptions=sum(len(x.get('exceptions',[])) for x in rows);warnings=sum(len(x.get('warnings',[])) for x in rows)
            success=sum(x.get('successes',0) for x in rows)
            out['conftest']={'status':'PASS' if r.returncode==0 and rows and success>0 and not(fail or exceptions or warnings) else 'FAIL',
                'reason':'REAL_PLAN_POLICY' if native else 'SYNTHETIC_PLAN_POLICY','failure_reasons':failure_reasons(rows)}
        except Exception:pass
        return out
