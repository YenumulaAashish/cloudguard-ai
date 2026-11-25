"""Reviewed local CI allowlist; not hosted proof or a malicious-code sandbox."""
import hashlib
import json
from pathlib import Path
from .runtime import ROOT
from .safety import inspect

MAX_FILE=131072
FILES={'offline': '.github/workflows/terraform-ci.yml', 'aws_plan': '.github/workflows/terraform-plan.yml', 'setup': '.github/actions/setup-tools/action.yml', 'quality': 'scripts/cloudguard/quality.py', 'offline_runner': 'scripts/run-offline.py', 'phase4_smoke': 'scripts/cloudguard/ci_fixtures.py', 'phase4_smoke_cli': 'scripts/verify-phase4-fixtures.py', 'tflint': '.tflint.hcl', 'checkov': '.checkov.yml', 'workload_lock': 'terraform/.terraform.lock.hcl', 'bootstrap_lock': 'bootstrap/aws-plan-role/.terraform.lock.hcl', 'plan_runner': 'scripts/aws-plan.py', 'planning': 'scripts/cloudguard/planning.py', 'phase5': 'scripts/cloudguard/phase5.py', 'public_findings': 'scripts/cloudguard/public_findings.py', 'finding_schema': 'security/public-findings.schema.json', 'plan_cli': 'scripts/integrate-plan.py', 'bootstrap_role': 'bootstrap/aws-plan-role/main.tf', 'unknown_policy': 'policies/terraform/unknowns.rego', 'data_analyzer': 'scripts/cloudguard/data_protection.py', 'policy_reasons': 'scripts/cloudguard/policy_reporting.py', 'evidence': 'scripts/cloudguard/evidence.py', 'policy_testing': 'scripts/cloudguard/policy_testing.py', 'authorization': 'scripts/cloudguard/authorization.py', 'authorization_cli': 'scripts/planning-authorization.py', 'authorization_admin': 'scripts/manage-planning-ledger.py', 'cleanup': 'scripts/clean.py', 'advisory_backend': 'scripts/cloudguard/live_advisory.py', 'control_catalog': 'scripts/cloudguard/control_catalog.py', 'control_descriptions': 'security/control-descriptions.json', 'authorization_template': 'security/planning-authorization.template.json', 'phase6_config': 'scripts/cloudguard/phase6/config.py', 'phase6_cost': 'scripts/cloudguard/phase6/cost.py', 'phase6_drift': 'scripts/cloudguard/phase6/drift.py', 'phase6_engine': 'scripts/cloudguard/phase6/engine.py', 'phase6_gates': 'scripts/cloudguard/phase6/gates.py', 'phase6_http': 'scripts/cloudguard/phase6/http.py', 'phase6_store': 'scripts/cloudguard/phase6/store.py', 'phase6___init__': 'scripts/cloudguard/phase6/__init__.py', 'phase6_cli': 'scripts/serve-provisioning-mock.py', 'phase6_schema': 'security/phase6-public.schema.json', 'phase6_prices': 'security/phase6-mock-prices.json', 'phase6_transport': 'frontend/src/services/provisioning.ts', 'phase6_privacy': 'frontend/scripts/check-safety.mjs', 'phase6_proxy': 'frontend/vite.config.ts'}
EXPECTED={'offline': '269ba766b49ada155c6b1c2407f4f200b1639b85694aea7c99647b978bdb0f07', 'aws_plan': 'c68e9fc6efad328c7acf04ddb72e4863a1c16a12ee95c61d863126634e959328', 'setup': '525648b8f426449cb742153c7c2020b6591b721563af57ec410079628e775f5d', 'quality': 'bf01f5ecd166c03b95cbb439ce3c1b73dd3f97e8138aa027cb4a12a9961f821d', 'offline_runner': 'aac3c526098b99afb46426490fe548083f8602f37d253afcdbf6f73973538b02', 'phase4_smoke': '878b6e8f64ac81d8c8a2bd38ab3a4a6d19c2794f98383cbb94008160aa16498d', 'phase4_smoke_cli': 'e8754c07c71b4ae27da6d89981bc87e3c4ba4a8623d365bc19eeaa751afbf925', 'tflint': '424289afe46421d641749587e76c14c511d9fefa7eaab1c4712acc17e9a078a5', 'checkov': '2f966c0a48d71cc8023860fabe7e604d58127a925e8b984f171f7dc08092ca38', 'workload_lock': 'a954d6eb37479efaaf0020f5724be94b49cf116cb387bf92830c1082be4cf82c', 'bootstrap_lock': 'a954d6eb37479efaaf0020f5724be94b49cf116cb387bf92830c1082be4cf82c', 'plan_runner': '4fe74676384b83665314602333b37ed235ed8a9c2053f7fee3b10603e47eea01', 'planning': 'b9389557a2aec1a1c29c5c3b642965387332424b449ea0172ae5249ce992e4e3', 'phase5': 'ea46b3b1d1eb23856da9373c47b8acb65dab00b08b359f6696cd877c01b05678', 'public_findings': 'dffdb55f7eda93b820fcade916ef50112527e95a7cf01f28817a31631fec06ec', 'finding_schema': '34b82b0df931c45619d2de696615cf2973f3c3de09dda92f2776ae59c19a88f0', 'plan_cli': 'ae3abf64643178698fd7f9c41fd2e67d348f6b97f5b0eeaadc44bb29099c1d67', 'bootstrap_role': '8d2fd9ce235a08cfa21ccef8ee77a20faedef891da130397e147a2dcdc07b041', 'unknown_policy': '62c563b10dae042cd14c6f152200424e9282dd13daeb685a5d1af269757e1b70', 'data_analyzer': '302d915ff0c86d0f78b788426f81ad4de42c8078e0fb10cabd95b40df290ed09', 'policy_reasons': '5904aee0945762d2ae8d6df0be8c5220677dbf577df25765deb41ff1bc85dc29', 'evidence': '2f98dcdf7499d16be3a794ef481da8f7d5e6df3a316d1be43555f8a667c4672c', 'policy_testing': '17f5d613ab1b3824931633d2b4461197d8fdac80d456cbc89f393513f2d923c0', 'authorization': '9045ac12c45720450b36f14aa9252f156c68ac509724fc127886fc165ba754d4', 'authorization_cli': '17cfbb50e362b6f8d854d6deeaabf6c61ffc5cf2ce6935daf91db87d35b8a561', 'authorization_admin': 'dc775495a70b0143dbb2e6bed9cd3d4f34e5979c279cfd27445bd6ecf2484b75', 'cleanup': 'd24b27df4142409b1f488e9cb68387a56f19fe7fbb4d0fff4d6c622fbd6ec0da', 'advisory_backend': 'b4d388823206d53201110ae7c92ff03581151feb20d7a3cddfbc6bc91d624140', 'control_catalog': 'abd5d4a4cfc1008e7313942d25d0bf5234e197ae0b10829a718d6cd064120661', 'control_descriptions': '79941c9a00e17af9729ca6718fcde369d4108271990035a9ad389b2f54e49df0', 'authorization_template': 'ea1513e87afa799e1e549b8aa480950cba6497957f10b4261c53172e5185787e', 'phase6_config': 'eba9615aaa31c263082a256f744e0d38a9095bb8f4e93b470b1ca6887e7a1add', 'phase6_cost': '45b7541a331f9af91badbe6b02481616b81dcd590c4e4fc0d2bfd69cd268cfc8', 'phase6_drift': 'dd9c1dc95a4f044a5a23e035599efe616b07dfe43cea3c1320042503da94c9fc', 'phase6_engine': '1457b9801587db86b01ca18a128934a67bbd4b4abda6bf9244ce0ddd50e94a99', 'phase6_gates': 'b5ca780a6f2b394410022d0ea568cd51f8f3492dd1701851e4643b3bf3a88cd5', 'phase6_http': '983f5062441d6fe026126bc8472530735799574f072cf756b0299bebcf5abbfb', 'phase6_store': '2e8dd266e4445b37e53681464c42b56272a684d4d55d2434a8e4f8309479b9b4', 'phase6___init__': '993e883fceef6ed57158d0183b2d15a35e78c85b597002cd8932b2af653bc4ed', 'phase6_cli': 'a0652afc53f7d59966676f4292ceff185726dd5dc4f48340298c39d630de38c7', 'phase6_schema': 'b6315df95be08e7be90aebe37f2a424d40b1e64049dc16bbdc6f693ff3123bf7', 'phase6_prices': '5ff6f9466f9f90e6eb5e0a85e09a507994003711c4d8d20c0661484a17ed9af7', 'phase6_transport': 'a16f96a7371039d7f23267b5ca599df0e052d61e0d19ad4ccafa9cfd54f862a2', 'phase6_privacy': '90d62d5e3f89a8b831e106eb9b164ce14ce144a30825e6c4f3c577531d8badc2', 'phase6_proxy': '32ab8bc959e659557ce409c6b69718e2e0837436a885281cfe74795e10d1c9fb'}


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
