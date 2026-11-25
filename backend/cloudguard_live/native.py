"""Fixed native Terraform commands; saved-plan execution exists only in this isolated worker.
Never imported by a GitHub workflow. Tests inject a process double; they do not deploy.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from cloudguard.runtime import ROOT,tool
from cloudguard.phase6.config import require,render_hcl

class Native:
    def __init__(self,authority,aws,process=subprocess.run):self.auth=authority;self.aws=aws;self.process=process
    def call(self,folder,args,tag,operation='plan',accepted=(0,)):
        self.auth.check(operation);creds=self.auth.credentials()
        env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        home=Path(folder)/'native-home';home.mkdir(exist_ok=True)
        env.update(creds,HOME=str(home),USERPROFILE=str(home),AWS_REGION='ap-south-1',AWS_DEFAULT_REGION='ap-south-1',AWS_EC2_METADATA_DISABLED='true',AWS_MAX_ATTEMPTS='1',CHECKPOINT_DISABLE='1',TF_IN_AUTOMATION='true')
        # Only local, lock-file-verified providers. No registry fallback or user CLI config.
        rc=Path(folder)/'native.tfrc';rc.write_text('disable_checkpoint = true\nprovider_installation { filesystem_mirror { path = '+json.dumps((ROOT/'terraform/.terraform/providers').as_posix())+' include = ["registry.terraform.io/hashicorp/aws"] } }\n',encoding='utf-8')
        env['TF_CLI_CONFIG_FILE']=str(rc)
        result=self.process(tool('terraform')+['-chdir='+str(Path(folder).resolve())]+args,env=env,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240,text=True,encoding='utf-8')
        (Path(folder)/(tag+'.private.log')).write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
        require(result.returncode in accepted,'NATIVE_OPERATION_FAILED')
        return result
    def prepare(self,folder,tf):
        c=self.auth.c
        (folder/'main.tf').write_text(render_hcl(tf)+'\nterraform {\n  backend "s3" {}\n}\n',encoding='utf-8')
        # Provider account pinning is enforced independently of the SDK identity check.
        text=(folder/'main.tf').read_text(encoding='utf-8').replace('region = "ap-south-1"','region = "ap-south-1"\n  max_retries = 0\n  allowed_account_ids = ["'+c['account_id']+'"]')
        (folder/'main.tf').write_text(text,encoding='utf-8')
        backend={'bucket':c['state_bucket'],'key':c['state_key'],'region':'ap-south-1','encrypt':True,'kms_key_id':c['state_kms_key'],'dynamodb_table':c['lock_table'],'allowed_account_ids':[c['account_id']]}
        (folder/'backend.json').write_text(json.dumps(backend),encoding='utf-8')
        shutil.copyfile(ROOT/'terraform/.terraform.lock.hcl',folder/'.terraform.lock.hcl')
        version=json.loads(self.call(folder,['version','-json'],'version').stdout)
        require(version.get('terraform_version')=='1.9.8','PINNED_TERRAFORM_REQUIRED')
        self.call(folder,['init','-input=false','-lockfile=readonly','-reconfigure','-backend-config=backend.json','-no-color'],'init')
        result=self.call(folder,['validate','-json'],'validate');require(json.loads(result.stdout).get('valid') is True,'NATIVE_VALIDATION_FAILED')
    def state(self,folder):
        c=self.auth.c
        try:self.aws.client('s3').head_object(Bucket=c['state_bucket'],Key=c['state_key'],ExpectedBucketOwner=c['account_id'])
        except Exception as exc:
            # Only a proven missing object means an initial empty state; never swallow AccessDenied.
            response=getattr(exc,'response',{})
            require(response.get('Error',{}).get('Code') in ('404','NoSuchKey','NotFound'),'STATE_OBSERVATION_UNAVAILABLE')
            return {'lineage':None,'serial':0,'sha256':None,'managed':[]}
        raw=self.call(folder,['state','pull'],'state').stdout;value=json.loads(raw)
        require(type(value.get('serial')) is int and value.get('lineage'),'STATE_OBSERVATION_UNAVAILABLE')
        managed=[]
        for r in value.get('resources',[]):
            if r.get('mode')!='managed':continue
            for instance in r.get('instances',[]):
                identity=instance.get('attributes',{}).get('id')
                if identity:managed.append([r['type'],identity])
        return {'lineage':value['lineage'],'serial':value['serial'],'sha256':hashlib.sha256(raw.encode()).hexdigest(),'managed':managed}
    def plan(self,folder,refresh=False):
        args=['plan','-input=false','-lock-timeout=30s','-detailed-exitcode','-out=validated.tfplan','-no-color']
        if refresh:args.append('-refresh-only')
        result=self.call(folder,args,'plan',accepted=(0,2))
        raw=self.call(folder,['show','-json','validated.tfplan'],'show').stdout
        (folder/'tfplan.json').write_text(raw,encoding='utf-8');plan=json.loads(raw)
        require(plan.get('terraform_version')=='1.9.8' and not plan.get('errored') and not plan.get('deferred_changes') and plan.get('complete',True) is True,'PLAN_INCOMPLETE')
        return plan
    def execute(self,folder,deleting=False):
        # The engine checks the consumed exact-plan record and authorization before reaching here.
        self.call(folder,['apply','-input=false','-lock-timeout=30s','-no-color','validated.tfplan'],'execution','delete' if deleting else 'deploy')
