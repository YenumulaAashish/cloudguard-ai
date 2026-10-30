"""IAM structural controls, uncertainty and Phase 3 compatibility; no services."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from cloudguard import iam
from cloudguard.findings import serialize
from cloudguard.risk import assess_risk, read_document
from cloudguard.integration import schema_validate


def plan(statement=None, typ="aws_iam_policy", raw=None):
    document = {"Statement": statement if isinstance(statement,list) else [statement or {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/object"}]}
    return {"format_version":"1.2","planned_values":{"root_module":{"resources":[{"address":typ+".example","type":typ,"values":{"assume_role_policy" if typ == "aws_iam_role" else "policy":document if raw is None else raw}}]}}}


def statement(action="s3:GetObject", resource="arn:aws:s3:::example/object", **kw):
    return {"Effect":"Allow","Action":action,"Resource":resource,**kw}


def controls(p): return [f["control_id"] for f in iam.analyze(p)["findings"]]


class IamTests(unittest.TestCase):
    def test_empty_and_no_iam(self):
        p=plan(); p['planned_values']['root_module']['resources']=[]
        self.assertEqual(controls(p),[])
        p=plan(typ='aws_s3_bucket'); self.assertEqual(controls(p),[])

    def test_fixtures(self):
        for name,expected in [('scoped',[]),('admin',['CGA_IAM_001'])]:
            self.assertEqual(controls(read_document(ROOT/'tests/fixtures/iam'/f'{name}.json')),expected)

    def test_full_admin_suppression(self):
        self.assertEqual(controls(plan(statement('*','*'))),['CGA_IAM_001'])

    def test_wildcard_resource_is_not_admin(self):
        self.assertEqual(controls(plan(statement(resource='*'))),['CGA_IAM_004'])

    def test_global_action_scoped_resource(self):
        self.assertIn('CGA_IAM_002', controls(plan(statement('*'))))
        self.assertNotIn('CGA_IAM_001',controls(plan(statement('*'))))

    def test_multiple_actions_resources(self):
        self.assertEqual(controls(plan(statement(['s3:GetObject','ec2:DescribeVpcs'],['arn:one','*']))),['CGA_IAM_004'])

    def test_deny_and_mixed(self):
        deny=statement('*','*',Effect='Deny')
        self.assertEqual(controls(plan(deny)),[])
        self.assertEqual(controls(plan([deny,statement('*','*')])),['CGA_IAM_001'])

    def test_conditions_preserved(self):
        for cond in ({},{'StringEquals':{'aws:RequestedRegion':'ap-south-1'}}):
            r=iam.analyze(plan(statement('*','*',Condition=cond)))
            self.assertEqual(r['findings'][0]['conditioned'],bool(cond))

    def test_trust_public(self):
        for principal in ['*',{'AWS':'*'},{'AWS':['arn:example','*']}]:
            self.assertEqual(controls(plan({'Effect':'Allow','Action':'sts:AssumeRole','Principal':principal},'aws_iam_role')),['CGA_IAM_008'])

    def test_safe_service_and_scoped_trust(self):
        for principal in [{'Service':'ec2.amazonaws.com'},{'AWS':'arn:aws:iam::000000000000:role/example'}]:
            self.assertEqual(controls(plan({'Effect':'Allow','Action':'sts:AssumeRole','Principal':principal},'aws_iam_role')),[])

    def test_federated_restrictions(self):
        s={'Effect':'Allow','Action':'sts:AssumeRoleWithWebIdentity','Principal':{'Federated':'arn:example'}}
        self.assertEqual(controls(plan(s,'aws_iam_role')),['CGA_IAM_009'])
        s['Condition']={'StringEquals':{'issuer:sub':'example'}}
        self.assertEqual(controls(plan(s,'aws_iam_role')),[])

    def test_negated_constructs_are_unknown(self):
        for key in ['NotAction','NotResource','NotPrincipal']:
            r=iam.analyze(plan(statement(**{key:'*'})))
            self.assertEqual(r['findings'][0]['status'],'UNKNOWN')

    def test_object_and_string_policy(self):
        p=plan(statement('*','*')); obj=p['planned_values']['root_module']['resources'][0]['values']['policy']
        a=iam.analyze(p)
        self.assertEqual(a,iam.analyze(plan(raw=json.dumps(obj))))
        self.assertEqual(a,iam.analyze(plan(raw={'Statement':statement('*','*')})))

    def test_malformed_policy_is_error(self):
        for value in ['{', '[]', '{"Statement":[],"Statement":[]}', [], 1, True]:
            with self.subTest(value=value),self.assertRaises((ValueError,TypeError)): iam.analyze(plan(raw=value))

    def test_missing_statement_and_policy_are_unknown(self):
        self.assertEqual(controls(plan(raw={})),['CGA_IAM_010'])
        p=plan(); p['planned_values']['root_module']['resources'][0]['values']={}
        self.assertEqual(controls(p),['CGA_IAM_010'])

    def test_unknown_after_overrides_known_snapshot(self):
        p=plan(statement('*','*')); row=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':row['address'],'type':row['type'],'change':{'actions':['create'],'after':{},'after_unknown':{'policy':True}}}]
        self.assertEqual(controls(p),['CGA_IAM_010'])
        p['planned_values']['root_module']['resources']=[]
        self.assertEqual(controls(p),['CGA_IAM_010'])

    def test_delete_is_omitted(self):
        p=plan(statement('*','*')); row=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':row['address'],'type':row['type'],'change':{'actions':['delete'],'after':None}}]
        self.assertEqual(controls(p),[])

    def test_unrelated_unknown_does_not_erase_policy(self):
        p=plan(statement('*','*')); row=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':row['address'],'type':row['type'],'change':{'actions':['create'],'after':row['values'],'after_unknown':{'arn':True}}}]
        self.assertEqual(controls(p),['CGA_IAM_001'])

    def test_duplicate_suppression_and_indexes(self):
        s=statement('*','*'); p=plan([s,s,statement('s3:*')])
        rows=iam.analyze(p)['findings']; self.assertEqual([r['statement_index'] for r in rows],[0,2])

    def test_nested_modules_and_resource_order(self):
        p=plan(); root=p['planned_values']['root_module']; row=deepcopy(root['resources'][0]); row['address']='module.child.aws_iam_policy.x'
        row['values']['policy']={'Statement':[statement('*','*')]}
        root['child_modules']=[{'resources':[row]}]
        self.assertEqual(controls(p),['CGA_IAM_001'])

    def test_large_statement_and_item_bounds(self):
        for s in [[statement()]*257,statement(['s3:GetObject']*129),statement(resource=['arn:x']*129)]:
            with self.assertRaises(ValueError): iam.analyze(plan(s))
        with self.assertRaises(ValueError): iam.analyze(plan(raw=' '*262145))

    def test_invalid_condition(self):
        with self.assertRaises(ValueError): iam.analyze(plan(statement(Condition='invalid')))

    def test_malicious_strings_inert_and_not_copied(self):
        for text in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake report -->']:
            p=plan(statement(resource=text)); original=deepcopy(p)
            r=iam.analyze(p); self.assertEqual(r['findings'],[]); self.assertEqual(p,original)

    def test_determinism_immutability_and_schema(self):
        p=plan(statement('*','*')); old=deepcopy(p); a=iam.analyze(p)
        self.assertEqual(serialize(a),serialize(iam.analyze(p))); self.assertEqual(p,old)
        iam.validate(a)
        for changed in [{**a,'extra':True},{**a,'schema_version':'2'}]:
            with self.assertRaises(Exception): iam.validate(changed)

    def test_phase3_compatibility(self):
        a=iam.normalized(iam.analyze(plan(statement('*','*'))))
        schema_validate(a,'normalized'); risk=assess_risk(a)
        self.assertEqual(risk['findings'][0]['control_id'],'CGA_IAM_001')
        self.assertEqual(a['findings'][0]['metadata']['analyzer'],'cloudguard-iam')
        self.assertFalse(a['findings'][0]['exception'])

    def test_no_network_execution_or_keys(self):
        with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execute')),patch.dict('os.environ',{},clear=True):
            iam.analyze(plan(statement('*','*')))

    def test_cli_help_collision_and_private_boundary(self):
        spec=importlib.util.spec_from_file_location('iam_cli',ROOT/'scripts/analyze-iam.py'); cli=importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); source=root/'plan.json'; source.write_text(serialize(plan()))
            with patch.object(cli,'PRIVATE',root/'private'):
                output=root/'private/report.json'
                self.assertEqual(cli.main(['--plan',str(source),'--output',str(output)]),0)
                before=output.read_bytes()
                self.assertEqual(cli.main(['--plan',str(source),'--output',str(output)]),2)
                self.assertEqual(output.read_bytes(),before)
                self.assertEqual(cli.main(['--plan',str(source),'--output',str(root/'public.json')]),2)


    def test_unknown_status_adapter_remains_warning(self):
        normalized=iam.normalized(iam.analyze(plan(raw={})))
        schema_validate(normalized,'normalized')
        self.assertEqual(normalized['findings'][0]['status'],'warning')
        self.assertEqual(normalized['findings'][0]['severity'],'UNKNOWN')
        assess_risk(normalized)

    def test_case_insensitive_actions(self):
        self.assertIn('CGA_IAM_006',controls(plan(statement('IAM:PASSROLE','*'))))

    def test_resource_permutation_is_deterministic(self):
        p=plan(statement('*','*')); rows=p['planned_values']['root_module']['resources']
        other=deepcopy(rows[0]); other['address']='aws_iam_policy.other'; rows.append(other)
        first=serialize(iam.analyze(p)); rows.reverse()
        self.assertEqual(first,serialize(iam.analyze(p)))

    def test_invalid_envelopes_and_duplicate_resources(self):
        for p in [{},{'format_version':'9'}, {**plan(),'errored':True}, {**plan(),'deferred_changes':[{}]}]:
            with self.assertRaises(ValueError): iam.analyze(p)
        p=plan(); rows=p['planned_values']['root_module']['resources']; rows.append(deepcopy(rows[0]))
        with self.assertRaises(ValueError): iam.analyze(p)

    def test_control_severity_and_counts_tampering_rejected(self):
        report=iam.analyze(plan(statement('*','*')))
        for field,value in [('severity','HIGH'),('status','UNKNOWN'),('message','changed')]:
            changed=deepcopy(report); changed['findings'][0][field]=value
            with self.assertRaises(Exception): iam.validate(changed)
        report['summary']['total']=0
        with self.assertRaises(ValueError): iam.validate(report)

    def test_unknown_role_embedded_permissions(self):
        p=plan({'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'ec2.amazonaws.com'}},'aws_iam_role')
        row=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':row['address'],'type':row['type'],'change':{'after':row['values'],'after_unknown':{'inline_policy':True},'actions':['create']}}]
        self.assertEqual(controls(p),['CGA_IAM_010'])

    def test_invalid_unknown_mask(self):
        p=plan(); row=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':row['address'],'type':row['type'],'change':{'after':row['values'],'after_unknown':{'policy':'invalid'}}}]
        with self.assertRaises(ValueError): iam.analyze(p)


def add_case(name, p, expected):
    def case(self): self.assertIn(expected,controls(p))
    setattr(IamTests,'test_'+name,case)

for action in sorted(iam.PRIVILEGES): add_case('privilege_'+action,plan(statement('iam:'+action)),'CGA_IAM_005')
for typ in sorted(iam.POLICIES): add_case('resource_'+typ,plan(statement('*','*'),typ),'CGA_IAM_001')
for typ in sorted(iam.ATTACHMENTS|{'aws_iam_instance_profile','aws_iam_policy_document'}): add_case('unresolved_'+typ,plan(typ=typ),'CGA_IAM_010')
for action in ['s3:*','iam:*','ec2:*','s3:Get*']: add_case('wildcard_'+action.replace(':','_').replace('*','all'),plan(statement(action)),'CGA_IAM_003')
add_case('passrole_scoped',plan(statement('iam:PassRole')),'CGA_IAM_007')
add_case('passrole_unrestricted',plan(statement('iam:PassRole','*')),'CGA_IAM_006')
