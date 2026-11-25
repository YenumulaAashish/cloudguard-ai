"""Actual offline tools for fixed Phase 6 templates; no AWS clients or credentials."""
import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path
from cloudguard.runtime import PRIVATE,ROOT,tool,write_json
from cloudguard.exceptions import terraform_report
from cloudguard.phase6.config import generate,render_hcl,mock_plan,canonical
from cloudguard.phase6.gates import ToolGates

def main():
    c={'project':'capstone','region':'ap-south-1','vpc':{'enabled':True,'cidr':'10.40.0.0/16','subnet_cidr':'10.40.1.0/24'},'ec2':{'enabled':True,'instance_type':'t3.micro','ami':'mock-al2023','root_gb':8,'hours':24},'s3':{'enabled':True,'storage_gb':1,'requests':1000,'transfer_gb':0},'budget_usd':'5.00'}
    results={}
    for case,vpc,ec2,s3 in [('all',True,True,True),('s3-only',False,False,True),('vpc-only',True,False,False)]:
        c['vpc']['enabled']=vpc;c['ec2']['enabled']=ec2;c['s3']['enabled']=s3
        folder=PRIVATE/'phase6-source'/case;folder.mkdir(parents=True,exist_ok=True)
        tf,resources=generate(c);(folder/'main.tf').write_text(render_hcl(tf),encoding='utf-8');(folder/'mock-plan.json').write_text(canonical(mock_plan(resources,{})),encoding='utf-8')
        results[case]=ToolGates().run(folder)
        print(case+': '+json.dumps(results[case],sort_keys=True),flush=True)
    # Prove every repaired category still rejects a missing control. These are
    # deliberately insecure private fixtures, never deployable configurations.
    c['vpc']['enabled']=c['ec2']['enabled']=c['s3']['enabled']=True
    base,_=generate(c)
    negative={}
    for rule,kind in [('CKV2_AWS_11','aws_flow_log'),('CKV2_AWS_41','profile'),('CKV2_AWS_62','aws_s3_bucket_notification'),('CKV_AWS_144','aws_s3_bucket_replication_configuration'),('CKV_AWS_145','encryption'),('CKV_AWS_18','aws_s3_bucket_logging')]:
        tf=deepcopy(base)
        if kind=='profile':tf['resource']['aws_instance']['this'].pop('iam_instance_profile')
        elif kind=='encryption':
            encryption=tf['resource']['aws_s3_bucket_server_side_encryption_configuration']['this']['rule'][0]['apply_server_side_encryption_by_default'][0]
            encryption['sse_algorithm']='AES256';encryption.pop('kms_master_key_id')
        else:tf['resource'].pop(kind)
        folder=PRIVATE/'phase6-source/negative'/rule;folder.mkdir(parents=True,exist_ok=True);home=folder/'tool-home';home.mkdir(exist_ok=True)
        (folder/'main.tf').write_text(render_hcl(tf),encoding='utf-8')
        env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','TEMP','TMP') if k in os.environ};env.update(HOME=str(home),USERPROFILE=str(home),AWS_EC2_METADATA_DISABLED='true',CHECKPOINT_DISABLE='1')
        with (folder/'checkov.stderr').open('w',encoding='utf-8') as err:
            r=subprocess.run(tool('checkov')+['-d',str(folder),'--config-file',str(ROOT/'.checkov.yml'),'--output','json'],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=err,text=True,timeout=120)
        (folder/'checkov.stdout').write_text(r.stdout,encoding='utf-8')
        report=terraform_report(json.loads(r.stdout));counts=report['summary'];failed={x['check_id'] for x in report['results']['failed_checks']}
        negative[rule]='PASS' if r.returncode==1 and rule in failed and counts['skipped']==counts['parsing_errors']==0 else 'FAIL'
        print(rule+' missing-control rejection: '+negative[rule],flush=True)
    write_json(PRIVATE/'phase6-source/negative-results.json',negative)
    write_json(PRIVATE/'phase6-source/results.json',results)
    return 0 if all(g['status']=='PASS' for case in results.values() for g in case.values()) and all(v=='PASS' for v in negative.values()) else 1
if __name__=='__main__':raise SystemExit(main())
