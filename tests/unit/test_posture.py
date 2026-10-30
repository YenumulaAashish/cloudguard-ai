"""Cross-report consistency, information minimization and completion safety."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import posture as p,iam,network,data_protection,security_graph
from cloudguard.findings import serialize
from cloudguard.risk import read_document


def reports(plan=None):
    plan=plan if plan is not None else read_document(ROOT/'tests/fixtures/graph/connected.json')
    values={'iam':iam.analyze(plan),'network':network.analyze(plan),'data':data_protection.analyze(plan)}
    values['graph']=security_graph.build(plan,values)
    return values

def plan(rows):return {'format_version':'1.2','planned_values':{'root_module':{'resources':rows}}}
def resource(typ,values):return {'address':typ+'.example','type':typ,'values':values}
def level_plan(level):
    if level=='NONE':return plan([])
    if level=='UNKNOWN':return plan([resource('aws_iam_role',{})])
    if level=='CRITICAL':return plan([resource('aws_iam_policy',{'policy':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}})])
    rule={'protocol':'tcp','from_port':22 if level=='HIGH' else 23,'to_port':22 if level=='HIGH' else 23,'cidr_blocks':['0.0.0.0/0']}
    if level=='LOW':rule['protocol']='-1'
    return plan([resource('aws_security_group',{'vpc_id':'external','ingress':[] if level=='LOW' else [rule],'egress':[rule] if level=='LOW' else []})])


class PostureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=reports()
    def test_valid_chain_and_finding_preservation(self):
        original=deepcopy(self.base);private,summary,receipt=p.prepare(original)
        self.assertEqual(original,self.base)
        for kind in ('iam','network','data'):self.assertEqual(private['findings'][kind],self.base[kind]['findings'])
        self.assertEqual(private['finding_associations'],self.base['graph']['finding_associations'])
        self.assertTrue(summary['informational_only']);self.assertEqual(receipt['status'],'COMPLETE')
        self.assertEqual(set(receipt['components'].values()),{'COMPLETE'})
        self.assertEqual(receipt['phase5_status'],'NOT_STARTED')

    def test_aggregation_never_adds_severity(self):
        r=reports(level_plan('HIGH'));extra=resource('aws_iam_policy',{'policy':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'arn:scoped'}]}})
        pl=level_plan('HIGH');pl['planned_values']['root_module']['resources'].append(extra)
        summary=p.prepare(reports(pl))[1];self.assertEqual(summary['overall']['category'],'HIGH')
        self.assertNotIn('score',summary['overall']);self.assertNotIn('risk',summary)

    def test_unknown_separate_from_known(self):
        pl=level_plan('HIGH');pl['planned_values']['root_module']['resources'].append(resource('aws_iam_role',{}))
        private,summary,_=p.prepare(reports(pl))
        self.assertEqual(summary['overall']['category'],'HIGH')
        self.assertEqual(summary['domains']['iam']['category'],'UNKNOWN');self.assertTrue(summary['overall']['requires_review'])

    def test_graph_only_unresolved_does_not_invent_severity(self):
        summary=p.prepare(reports(plan([resource('aws_subnet',{'vpc_id':'external'})])))[1]
        self.assertEqual(summary['overall']['category'],'NONE');self.assertTrue(summary['graph']['requires_review'])

    def test_domain_maximum_independent_of_finding_order(self):
        report=deepcopy(self.base['iam']);before=p.domain(report);report['findings'].reverse()
        self.assertEqual(p.domain(report),before)

    def test_context_always_unknown_not_attestation(self):
        private,summary,receipt=p.prepare(self.base)
        for key in ('same_plan','freshness','authenticity'):self.assertEqual(private['analysis_context'][key],'UNKNOWN')
        self.assertEqual(summary['context_status'],'UNKNOWN');self.assertEqual(receipt['context_status'],'UNKNOWN')
        self.assertNotIn('plan_fingerprint',private['analysis_context'])
        for kind,report in self.base.items():self.assertEqual(private['analysis_context']['report_fingerprints'][kind],hashlib.sha256(serialize(report).encode()).hexdigest())

    def test_fingerprint_records_changed_content_without_freshness_claim(self):
        r=deepcopy(self.base);r['iam']['findings'][0]['conditioned']=not r['iam']['findings'][0]['conditioned']
        a=p.prepare(self.base)[0]['analysis_context'];b=p.prepare(r)[0]['analysis_context']
        self.assertNotEqual(a['report_fingerprints']['iam'],b['report_fingerprints']['iam']);self.assertEqual(b['freshness'],'UNKNOWN')

    def test_no_rerun_analyzers_or_graph(self):
        with patch.object(iam,'analyze',side_effect=AssertionError('rerun')),patch.object(network,'analyze',side_effect=AssertionError('rerun')),patch.object(data_protection,'analyze',side_effect=AssertionError('rerun')),patch.object(security_graph,'build',side_effect=AssertionError('rerun')):
            p.prepare(self.base)

    def test_input_missing_and_extra_components(self):
        for kind in self.base:
            r=deepcopy(self.base);del r[kind]
            with self.assertRaises(ValueError):p.prepare(r)
        with self.assertRaises(ValueError):p.prepare({**self.base,'extra':{}})

    def test_malformed_all_input_schemas(self):
        for kind in self.base:
            for bad in [{},{**self.base[kind],'schema_version':'9'},{**self.base[kind],'private_extra':'inert'}]:
                r=deepcopy(self.base);r[kind]=bad
                with self.subTest(kind=kind),self.assertRaises(Exception):p.prepare(r)

    def test_wrong_producer(self):
        for kind in self.base:
            r=deepcopy(self.base);r[kind]['builder' if kind=='graph' else 'analyzer']='fake'
            with self.assertRaises(Exception):p.prepare(r)

    def test_inconsistent_counts(self):
        for kind in self.base:
            r=deepcopy(self.base);r[kind]['summary']['nodes' if kind=='graph' else 'total']+=1
            with self.assertRaises(ValueError):p.prepare(r)

    def test_duplicate_input_findings_rejected(self):
        for kind in ('iam','network','data'):
            r=deepcopy(self.base);r[kind]['findings'].append(deepcopy(r[kind]['findings'][0]))
            r[kind]['summary']=p.ANALYZERS[kind].summary(r[kind]['findings'])
            with self.assertRaises(ValueError):p.prepare(r)

    def test_graph_association_missing_extra_and_severity_mismatch(self):
        for mutate in [lambda g:g['finding_associations'].pop(),lambda g:g['finding_associations'].append(deepcopy(g['finding_associations'][0])),lambda g:g['finding_associations'][0].update(severity='LOW'),lambda g:g['finding_associations'][0].update(control_id='CGA_IAM_999'),lambda g:g['finding_associations'][0].update(status='FINDING')]:
            r=deepcopy(self.base);mutate(r['graph']);r['graph']['summary']['finding_associations']=len(r['graph']['finding_associations'])
            with self.assertRaises(ValueError):p.prepare(r)

    def test_unmatched_finding_rejected(self):
        for kind in ('iam','network','data'):
            r=deepcopy(self.base);r[kind]['findings'][0]['resource']='unrelated.resource'
            with self.assertRaises(ValueError):p.prepare(r)

    def test_data_check_duplicates_or_missing_rejected(self):
        for operation in ['duplicate','missing']:
            r=deepcopy(self.base)
            if operation=='duplicate':r['data']['checks'].append(deepcopy(r['data']['checks'][0]))
            else:r['data']['checks'].pop()
            with self.assertRaises(ValueError):p.prepare(r)

    def test_graph_unresolved_duplicates_rejected(self):
        r=reports(plan([resource('aws_subnet',{'vpc_id':'external'})]));r['graph']['unresolved']*=2;r['graph']['summary']['unresolved']=2
        with self.assertRaises(ValueError):p.prepare(r)

    def test_schemas_and_extra_output_fields(self):
        for kind,value in zip(('private','summary','completion'),p.prepare(self.base)):
            p.schema_validate(value,kind)
            for changed in [{**value,'extra':'fake'},{**value,'informational_only':False}]:
                with self.assertRaises(Exception):p.schema_validate(changed,kind)
        receipt=p.prepare(self.base)[2];receipt['status']='PARTIAL'
        with self.assertRaises(Exception):p.schema_validate(receipt,'completion')

    def test_private_and_public_bytes_deterministic(self):
        self.assertEqual(tuple(map(serialize,p.prepare(self.base))),tuple(map(serialize,p.prepare(deepcopy(self.base)))))

    def test_bounds(self):
        for constant,value in [('MAX_INPUT',1),('MAX_FINDINGS',0),('MAX_PRIVATE',1),('MAX_PUBLIC',1)]:
            with patch.object(p,constant,value),self.assertRaises(ValueError):p.prepare(self.base)

    def test_sanitized_projection_no_private_text_or_topology(self):
        private,summary,receipt=p.prepare(self.base);text=serialize(summary)+serialize(receipt)
        for token in ['aws_instance.example','sg-fixture','subnet-fixture','vpc-fixture','fixture-bucket','profile-fixture','role-fixture','arn:aws','000000000000','0.0.0.0/0','edges','nodes','message','report_fingerprints']:
            self.assertNotIn(token,text)
        self.assertLessEqual(len(serialize(summary).encode()),4096)

    def test_malicious_identity_stays_private(self):
        for sentinel in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake completion -->','`rm -rf /`','AKIAEXAMPLEFAKEKEY']:
            r=deepcopy(self.base);old='aws_iam_policy.example'
            # Consistently rename one node/finding in all supplied reports.
            for f in r['iam']['findings']:
                if f['resource']==old:f['resource']=sentinel
            for node in r['graph']['nodes']:
                if node['id']==old:node['id']=sentinel
            for edge in r['graph']['edges']:
                for k in ('source','target'):
                    if edge[k]==old:edge[k]=sentinel
            for association in r['graph']['finding_associations']:
                if association['node']==old:association['node']=sentinel
            private,summary,receipt=p.prepare(r)
            self.assertTrue(any(f['resource']==sentinel for f in private['findings']['iam']));self.assertNotIn(sentinel,serialize(summary)+serialize(receipt))

    def test_invalid_messages_rejected_before_any_public_output(self):
        for kind in ('iam','network','data'):
            r=deepcopy(self.base);r[kind]['findings'][0]['message']='fake receipt terraform apply secret'
            with self.assertRaises(Exception):p.prepare(r)

    def test_no_network_execution_keys_or_ai(self):
        with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execute')),patch.dict('os.environ',{},clear=True):p.prepare(self.base)

    def test_conflicting_duplicate_identity_rejected(self):
        r=deepcopy(self.base);duplicate=deepcopy(r['iam']['findings'][0]);duplicate['conditioned']=not duplicate['conditioned']
        r['iam']['findings'].append(duplicate);r['iam']['summary']=iam.summary(r['iam']['findings'])
        with self.assertRaises(ValueError):p.prepare(r)

    def test_missing_all_graph_associations_rejected(self):
        r=deepcopy(self.base);r['graph']['finding_associations']=[];r['graph']['summary']['finding_associations']=0
        with self.assertRaises(ValueError):p.prepare(r)

    def test_untested_phase_status_or_verified_context_rejected(self):
        private,summary,receipt=p.prepare(self.base)
        private['analysis_context']['same_plan']='VERIFIED'
        with self.assertRaises(Exception):p.schema_validate(private,'private')
        receipt['components']['4.5']='INCOMPLETE'
        with self.assertRaises(Exception):p.schema_validate(receipt,'completion')
        summary['overall']['category']='SCORE_99'
        with self.assertRaises(Exception):p.schema_validate(summary,'summary')

    def test_absolute_paths_rejected_even_in_forged_graph(self):
        for address in ['/private/source.tf','C:/private/source.tf']:
            r=reports(plan([resource('aws_vpc',{'id':'known'})]));r['graph']['nodes'][0]['id']=address
            with self.assertRaises(ValueError):p.prepare(r)

    def test_public_canaries_removed_by_minimization(self):
        for canary in ['secret-bucket-name','secret-role-name','secret-policy-name','sg-secret','subnet-secret','vpc-secret','000000000123','arn:aws:iam::000000000123:role/secret','10.91.0.0/16','Bearer synthetic-token','ghp_synthetic-token','AWS_SECRET_ACCESS_KEY=synthetic']:
            r=deepcopy(self.base);old='aws_iam_policy.example'
            for f in r['iam']['findings']:
                if f['resource']==old:f['resource']=canary
            for node in r['graph']['nodes']:
                if node['id']==old:node['id']=canary
            for edge in r['graph']['edges']:
                for key in ('source','target'):
                    if edge[key]==old:edge[key]=canary
            for a in r['graph']['finding_associations']:
                if a['node']==old:a['node']=canary
            private,summary,receipt=p.prepare(r)
            self.assertNotIn(canary,serialize(summary)+serialize(receipt))


    def test_actual_finding_limit_and_oversized_input(self):
        r=deepcopy(self.base);r['iam']['findings']=[deepcopy(r['iam']['findings'][0]) for _ in range(4097)]
        r['iam']['summary']=iam.summary(r['iam']['findings'])
        with self.assertRaises(ValueError):p.prepare(r)
        r=deepcopy(self.base);r['graph']['oversized']='x'*(p.MAX_INPUT+1)
        with self.assertRaises(ValueError):p.prepare(r)

    def test_summary_has_no_premature_phase_completion(self):
        _,summary,receipt=p.prepare(self.base)
        self.assertNotIn('status',summary);self.assertNotIn('phase_status',summary)
        self.assertEqual(summary['completion_requirement'],'VALID_RECEIPT_REQUIRED')
        self.assertEqual(receipt['status'],'COMPLETE')

    def test_data_unknown_check_review_is_visible(self):
        pl=plan([resource('aws_s3_bucket',{})]);summary=p.prepare(reports(pl))[1]
        self.assertEqual(summary['domains']['data']['category'],'UNKNOWN')
        self.assertEqual(summary['domains']['data']['unknown_context_count'],8)
        self.assertTrue(summary['domains']['data']['requires_review'])



class PublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=reports()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.private=self.root/'reports/private/run';self.public=self.root/'reports/sanitized/run'
    def publish(self):return p.publish(self.base,self.private,self.public,root=self.root)
    def test_success_exact_files_and_completion(self):
        self.publish();self.assertEqual({x.name for x in self.private.iterdir()},{'posture.json'})
        self.assertEqual({x.name for x in self.public.iterdir()},{'posture-summary.json','phase4-completion.json'})
    def test_collision_preserves_existing_outputs(self):
        self.publish();before={x:x.read_bytes() for x in self.root.rglob('*.json')}
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(before,{x:x.read_bytes() for x in self.root.rglob('*.json')})
    def test_existing_empty_directory_collision(self):
        self.public.mkdir(parents=True)
        with self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.private.exists())
    def test_wrong_boundaries(self):
        with self.assertRaises(ValueError):p.publish(self.base,self.public,self.private,root=self.root)
        self.assertFalse(self.private.exists())
    def test_invalid_inputs_create_no_output(self):
        with patch.object(p,'validate_inputs',side_effect=ValueError('bad')):
            with self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.private.exists());self.assertFalse(self.public.exists())
    def test_write_failure_cleanup(self):
        original=p.write_file
        for fail_at in (1,2,3):
            calls=[]
            def broken(path,text):
                original(path,text);calls.append(path)
                if len(calls)==fail_at:raise OSError('failure')
            with patch.object(p,'write_file',side_effect=broken),self.assertRaises(OSError):self.publish()
            self.assertFalse(self.private.exists());self.assertFalse(self.public.exists())
    def test_receipt_last(self):
        original=p.write_file;order=[]
        def observe(path,text):
            self.assertFalse((self.public/'phase4-completion.json').exists());order.append(path.name);original(path,text)
        with patch.object(p,'write_file',side_effect=observe):self.publish()
        self.assertEqual(order[-1],'.phase4-completion.tmp')
    def test_rename_failure_cleanup(self):
        with patch.object(Path,'rename',side_effect=OSError('rename')),self.assertRaises(OSError):self.publish()
        self.assertFalse(self.private.exists());self.assertFalse(self.public.exists())
    def test_tampered_readback_cleanup(self):
        original=p.write_file
        def tamper(path,text):original(path,text+' ' if path.name=='posture-summary.json' else text)
        with patch.object(p,'write_file',side_effect=tamper),self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.public.exists())
    def test_nondeterministic_generation_no_outputs(self):
        original=p.prepare;calls=[]
        def vary(inputs):
            value=original(inputs);calls.append(1);value[1]['overall']['category']='LOW' if len(calls)==1 else 'HIGH';return value
        with patch.object(p,'prepare',side_effect=vary),self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.private.exists())
    def test_two_runs_all_bytes_identical(self):
        self.publish();p.publish(self.base,self.root/'reports/private/repeat',self.root/'reports/sanitized/repeat',root=self.root)
        for a,b in [(self.private,self.root/'reports/private/repeat'),(self.public,self.root/'reports/sanitized/repeat')]:
            for path in a.iterdir():self.assertEqual(path.read_bytes(),(b/path.name).read_bytes())


class CliTests(unittest.TestCase):
    def test_help_required_and_success(self):
        spec=importlib.util.spec_from_file_location('phase4_cli',ROOT/'scripts/run-phase4.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with self.assertRaises(SystemExit) as result:cli.main(['--help'])
        self.assertEqual(result.exception.code,0)
        with self.assertRaises(SystemExit) as result:cli.main([])
        self.assertEqual(result.exception.code,2)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);args=[]
            for kind,report in reports().items():
                path=root/(kind+'.json');path.write_text(serialize(report));args+=['--'+kind+'-report',str(path)]
            def local_publish(*args,**kw):return p.publish(*args,**kw,root=root)
            with patch.object(cli,'publish',side_effect=local_publish):
                args+=['--private-output-dir',str(root/'reports/private/run'),'--sanitized-output-dir',str(root/'reports/sanitized/run')]
                self.assertEqual(cli.main(args),0);self.assertEqual(cli.main(args),2)


def add_level(level):
    def case(self):
        _,summary,_=p.prepare(reports(level_plan(level)))
        self.assertEqual(summary['overall']['category'],level);self.assertTrue(summary['overall']['requires_review'])
    setattr(PostureTests,'test_overall_'+level,case)
for level in p.LEVELS+('UNKNOWN',):add_level(level)
