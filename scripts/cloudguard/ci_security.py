"""Reviewed local CI allowlist; not hosted proof or a malicious-code sandbox."""
import hashlib
import json
from pathlib import Path
from .runtime import ROOT
from .safety import inspect

MAX_FILE=131072
FILES={'offline': '.github/workflows/terraform-ci.yml', 'aws_plan': '.github/workflows/terraform-plan.yml', 'setup': '.github/actions/setup-tools/action.yml', 'quality': 'scripts/cloudguard/quality.py', 'offline_runner': 'scripts/run-offline.py', 'phase4_smoke': 'scripts/cloudguard/ci_fixtures.py', 'phase4_smoke_cli': 'scripts/verify-phase4-fixtures.py', 'tflint': '.tflint.hcl', 'checkov': '.checkov.yml', 'workload_lock': 'terraform/.terraform.lock.hcl', 'bootstrap_lock': 'bootstrap/aws-plan-role/.terraform.lock.hcl'}
EXPECTED={'offline': 'b210745b61a6746ad8ff0ca843b05802c0761e6b732544594453348c8ed1ec86', 'aws_plan': '5c257b4e260cb6c0f1563239139711ae63679264e9013b03272d2986fd6fc16c', 'setup': '528edbafcc56affd620374eaca106d854c61d494b03cd1c074417d4b317f3d97', 'quality': 'bf01f5ecd166c03b95cbb439ce3c1b73dd3f97e8138aa027cb4a12a9961f821d', 'offline_runner': 'aac3c526098b99afb46426490fe548083f8602f37d253afcdbf6f73973538b02', 'phase4_smoke': '878b6e8f64ac81d8c8a2bd38ab3a4a6d19c2794f98383cbb94008160aa16498d', 'phase4_smoke_cli': 'e8754c07c71b4ae27da6d89981bc87e3c4ba4a8623d365bc19eeaa751afbf925', 'tflint': '424289afe46421d641749587e76c14c511d9fefa7eaab1c4712acc17e9a078a5', 'checkov': '2f966c0a48d71cc8023860fabe7e604d58127a925e8b984f171f7dc08092ca38', 'workload_lock': 'a954d6eb37479efaaf0020f5724be94b49cf116cb387bf92830c1082be4cf82c', 'bootstrap_lock': 'a954d6eb37479efaaf0020f5724be94b49cf116cb387bf92830c1082be4cf82c'}


def require(test):
    if not test:raise ValueError('Invalid CI contract')


def load_yaml(text):
    import yaml
    class UniqueLoader(yaml.BaseLoader):
        def construct_mapping(self,node,deep=False):
            result={}
            for key,value in node.value:
                name=self.construct_object(key,deep=deep)
                require(isinstance(name,str) and name not in result)
                result[name]=self.construct_object(value,deep=deep)
            return result
    count=0
    for token in yaml.scan(text):
        count+=1;require(count<=32768)
        require(not isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken,yaml.tokens.TagToken)))
    value=yaml.load(text,Loader=UniqueLoader)
    require(isinstance(value,dict));return value


def verify(root=ROOT):
    root=Path(root);errors=[]
    try:
        names={p.name for p in (root/'.github/workflows').iterdir() if p.is_file()}
        if names!={'terraform-ci.yml','terraform-plan.yml'}:errors.append('WORKFLOW_SET_CHANGED')
    except OSError:errors.append('WORKFLOWS_UNAVAILABLE')
    for key,name in FILES.items():
        try:
            with (root/name).open('rb') as handle:raw=handle.read(MAX_FILE+1)
            require(len(raw)<=MAX_FILE)
            text=raw.decode('utf-8-sig').replace('\r\n','\n')
            canonical=json.dumps(load_yaml(text),sort_keys=True,separators=(',',':')) if key in ('offline','aws_plan','setup') else text
            if hashlib.sha256(canonical.encode()).hexdigest()!=EXPECTED[key]:errors.append(key.upper()+'_CONTRACT_CHANGED')
        except Exception:errors.append(key.upper()+'_INVALID_OR_MISSING')
    try:
        if inspect(root) or inspect(root,suppression=True):errors.append('EXISTING_SAFETY_GUARD_FAILED')
    except Exception:errors.append('EXISTING_SAFETY_GUARD_UNAVAILABLE')
    return {'result':'FAIL' if errors else 'PASS','scope':'LOCAL_STATIC_ONLY','hosted_execution':'NOT_RUN','errors':sorted(set(errors))}
