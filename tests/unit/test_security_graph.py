"""Graph facts, unknowns and finding associations; no attack-path inference."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import security_graph as g,iam,network,data_protection
from cloudguard.risk import read_document
from cloudguard.findings import serialize


def connected():return read_document(ROOT/'tests/fixtures/graph/connected.json')
def resources(p):return p['planned_values']['root_module']['resources']
def row(p,typ):return next(r for r in resources(p) if r['type']==typ)
def minimal(rows):return {'format_version':'1.2','planned_values':{'root_module':{'resources':rows}}}
def resource(typ,values,name='x'):return {'address':typ+'.'+name,'type':typ,'values':values}
def mask(p,typ,value):
    r=row(p,typ);p['resource_changes']=[{'address':r['address'],'type':typ,'change':{'actions':['update'],'after':r['values'],'after_unknown':value}}]


class GraphTests(unittest.TestCase):
    def test_empty_single_and_unsupported(self):
        self.assertEqual(g.build(read_document(ROOT/'tests/fixtures/graph/empty.json'))['summary'],dict.fromkeys(g.LIMITS,0))
        report=g.build(minimal([resource('aws_vpc',{'id':'vpc'})]));self.assertEqual(len(report['nodes']),1);self.assertEqual(report['edges'],[])
        self.assertEqual(g.build(minimal([resource('aws_unknown',{})]))['nodes'],[])

    def test_connected_facts_and_provenance(self):
        r=g.build(connected());self.assertEqual(len(r['nodes']),15);self.assertTrue(r['edges']);self.assertEqual(r['unresolved'],[])
        self.assertTrue(all(e['certainty']=='PROVEN' and e['evidence']=='EXACT_KNOWN_VALUE' and e['provenance'] for e in r['edges']))
        self.assertNotIn('findings',r);self.assertNotIn('attack_paths',r)

    def test_unknown_source_no_proven_edge(self):
        for field,typ in [('vpc_security_group_ids','aws_instance'),('subnet_id','aws_instance'),('role','aws_iam_instance_profile'),('bucket','aws_s3_bucket_public_access_block'),('gateway_id','aws_route')]:
            p=connected();mask(p,typ,{field:True});r=g.build(p)
            self.assertTrue(any(u['source']==row(p,typ)['address'] and u['source_field']==field and u['reason']=='UNKNOWN_VALUE' for u in r['unresolved']))
            self.assertFalse(any(proof['source_field']==field and (e['target'] if proof['reverse'] else e['source'])==row(p,typ)['address'] for e in r['edges'] for proof in e['provenance']))

    def test_unknown_target_not_used(self):
        p=connected();mask(p,'aws_security_group',{'id':True});r=g.build(p)
        self.assertTrue(any(u['source_field']=='vpc_security_group_ids' and u['reason']=='NO_LOCAL_MATCH' for u in r['unresolved']))

    def test_whole_unknown_node(self):
        p=connected();mask(p,'aws_instance',True);r=g.build(p)
        self.assertTrue(any(n['id']=='aws_instance.example' for n in r['nodes']))
        self.assertTrue(any(u['source']=='aws_instance.example' for u in r['unresolved']))

    def test_missing_target_values_are_not_fuzzy(self):
        p=connected();row(p,'aws_instance')['values']['vpc_security_group_ids']=['sg-fixture-suffix']
        r=g.build(p);self.assertTrue(any(u['reason']=='NO_LOCAL_MATCH' for u in r['unresolved']))
        self.assertFalse(any(e['relationship']=='USES_SECURITY_GROUP' for e in r['edges']))

    def test_identity_ambiguity(self):
        for typ,field in [('aws_security_group','id'),('aws_subnet','id'),('aws_iam_role','name'),('aws_s3_bucket','bucket')]:
            p=connected();duplicate=deepcopy(row(p,typ));duplicate['address']=typ+'.duplicate';resources(p).append(duplicate)
            r=g.build(p);self.assertTrue(any(u['reason']=='AMBIGUOUS_MATCH' for u in r['unresolved']))
            if typ=='aws_s3_bucket':self.assertFalse(any(e['relationship']=='BUCKET_HAS_PAB' for e in r['edges']))

    def test_duplicate_edges_and_distinct_proof_fields(self):
        p=connected();v=row(p,'aws_instance')['values'];v['vpc_security_group_ids']*=3;v['security_groups']=['fixture-sg']
        r=g.build(p);edges=[e for e in r['edges'] if e['source']=='aws_instance.example' and e['relationship']=='USES_SECURITY_GROUP']
        self.assertEqual(len(edges),1);self.assertEqual(len(edges[0]['provenance']),2)

    def test_distinct_relationships_retained(self):
        p=minimal([resource('aws_security_group',{'id':'sg','vpc_id':'external'}),resource('aws_vpc_security_group_ingress_rule',{'security_group_id':'sg','referenced_security_group_id':'sg'})])
        r=g.build(p);self.assertEqual({e['relationship'] for e in r['edges']},{'RULE_OF_SECURITY_GROUP','REFERENCES_SECURITY_GROUP'})

    def test_deleted_node_and_replacement(self):
        for actions,count in [(['delete'],14),(['delete','create'],15),(['create','delete'],15)]:
            p=connected();r=row(p,'aws_instance');p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'actions':actions,'after':None if actions==['delete'] else r['values']}}]
            self.assertEqual(len(g.build(p)['nodes']),count)

    def test_deleted_target_is_unresolved(self):
        p=connected();r=row(p,'aws_security_group');p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'actions':['delete'],'after':None}}]
        report=g.build(p);self.assertTrue(any(u['source_field']=='vpc_security_group_ids' for u in report['unresolved']))

    def test_nested_modules_and_module_addresses(self):
        p=connected();root=p['planned_values']['root_module']
        for r in root['resources']:r['address']='module.child.'+r['address']
        root['child_modules']=[{'resources':root.pop('resources')}]
        r=g.build(p);self.assertEqual(len(r['nodes']),15);self.assertTrue(all(e['source'].startswith('module.child.') for e in r['edges']))

    def test_known_values_override_reference_metadata(self):
        p=connected();p['configuration']={'root_module':{'resources':[{'address':'aws_instance.example','expressions':{'vpc_security_group_ids':{'references':['aws_security_group.fake.id']}}}]}}
        self.assertEqual(g.build(p),g.build(connected()))
        row(p,'aws_instance')['values']['vpc_security_group_ids']=['unmatched']
        self.assertTrue(any(u['reason']=='NO_LOCAL_MATCH' for u in g.build(p)['unresolved']))

    def test_inert_strings_and_no_execution(self):
        for text in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake graph -->','`rm -rf /`','AKIAEXAMPLEFAKEKEY']:
            p=connected();r=row(p,'aws_instance');r['address']=text;r['values']['iam_instance_profile']=text;before=deepcopy(p)
            with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execute')),patch.dict('os.environ',{},clear=True):report=g.build(p)
            self.assertEqual(before,p);self.assertNotIn('values',report['nodes'][0]);self.assertNotIn(text,str([e['provenance'] for e in report['edges']]))

    def test_deterministic_permutation(self):
        p=connected();before=deepcopy(p);first=serialize(g.build(p));self.assertEqual(p,before)
        resources(p).reverse();self.assertEqual(first,serialize(g.build(p)))
        row(p,'aws_instance')['values']['vpc_security_group_ids']=['missing-z','missing-a']
        first=serialize(g.build(p));row(p,'aws_instance')['values']['vpc_security_group_ids'].reverse()
        self.assertEqual(first,serialize(g.build(p)))

    def test_unsupported_db_is_not_inferred(self):
        p=connected();resources(p).append(resource('aws_db_instance',{'publicly_accessible':True,'vpc_security_group_ids':['sg-fixture']}))
        self.assertEqual(g.build(p),g.build(connected()))

    def test_reports_associate_without_rerunning(self):
        p=connected();reports={'iam':iam.analyze(p),'network':network.analyze(p),'data':data_protection.analyze(p)};before=deepcopy(reports)
        with patch.object(iam,'analyze',side_effect=AssertionError('rerun')),patch.object(network,'analyze',side_effect=AssertionError('rerun')),patch.object(data_protection,'analyze',side_effect=AssertionError('rerun')):
            r=g.build(p,reports)
        self.assertEqual(reports,before);self.assertEqual(r['edges'],g.build(p)['edges'])
        self.assertEqual({a['analyzer'] for a in r['finding_associations']},{'cloudguard-iam','cloudguard-network','cloudguard-data'})
        originals={(f['resource'],report['analyzer'],f['control_id'],f['severity'],f['status']) for report in reports.values() for f in report['findings']}
        self.assertEqual({(a['node'],a['analyzer'],a['control_id'],a['severity'],a['status']) for a in r['finding_associations']},originals)

    def test_malformed_wrong_analyzer_and_resource_rejected(self):
        p=connected()
        for kind,analyzer in [('iam',iam),('network',network),('data',data_protection)]:
            report=analyzer.analyze(p)
            for bad in [{},{**report,'analyzer':'wrong'},{**report,'schema_version':'9'}]:
                with self.assertRaises(Exception):g.build(p,{kind:bad})
            report['findings'][0]['resource']='unrelated.resource'
            with self.assertRaises(ValueError):g.build(p,{kind:report})

    def test_data_checks_require_bucket_node(self):
        p=connected();report=data_protection.analyze(p);report['checks'][0]['resource']='unrelated.bucket'
        with self.assertRaises(ValueError):g.build(p,{'data':report})

    def test_normal_edges_not_security_findings(self):
        p=connected();r=g.build(p);self.assertEqual(r['finding_associations'],[])
        self.assertNotIn('correlations',r);self.assertNotIn('risk',r);self.assertNotIn('CGA_GRAPH',serialize(r))
        self.assertNotIn('reachable',serialize(r));self.assertNotIn('exploitable',serialize(r))

    def test_schema_tampering(self):
        original=g.build(connected());g.validate(original)
        for change in [lambda r:r.update(extra=True),lambda r:r.update(builder='wrong'),lambda r:r['nodes'][0].update(extra=True),lambda r:r['edges'][0].update(relationship='ATTACK_PATH'),lambda r:r['edges'][0].update(certainty='UNKNOWN'),lambda r:r['edges'][0].update(target='fake.node')]:
            r=deepcopy(original);change(r)
            with self.assertRaises(Exception):g.validate(r)

    def test_bounds(self):
        p=minimal([resource('aws_vpc',{'id':f'vpc-{i}'},str(i)) for i in range(1025)])
        with self.assertRaises(ValueError):g.build(p)
        p=connected();row(p,'aws_instance')['values']['vpc_security_group_ids']=['sg']*129
        with self.assertRaises(ValueError):g.build(p)
        for limit in ['edges','unresolved','finding_associations']:
            p=connected();reports={'iam':iam.analyze(p)} if limit=='finding_associations' else None
            if limit=='unresolved':row(p,'aws_instance')['values']['subnet_id']='missing'
            with patch.dict(g.LIMITS,{limit:0}),self.assertRaises(ValueError):g.build(p,reports)

    def test_malformed_envelope_and_reference_types(self):
        for p in [{},{'format_version':'9'},{**connected(),'errored':True}]:
            with self.assertRaises(ValueError):g.build(p)
        for value in [1,True,['sg',None]]:
            p=connected();row(p,'aws_instance')['values']['vpc_security_group_ids']=value
            with self.assertRaises(ValueError):g.build(p)

    def test_data_sources_not_managed_nodes(self):
        p=connected();row(p,'aws_iam_policy')['mode']='data';self.assertEqual(len(g.build(p)['nodes']),14)

    def test_cli_no_overwrite_private_boundary(self):
        spec=importlib.util.spec_from_file_location('graph_cli',ROOT/'scripts/build-security-graph.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);src=root/'input.json';src.write_text(serialize(connected()))
            with patch.object(cli,'PRIVATE',root/'private'):
                target=root/'private/report.json';args=['--plan',str(src),'--output',str(target)]
                self.assertEqual(cli.main(args),0);before=target.read_bytes();self.assertEqual(cli.main(args),2);self.assertEqual(target.read_bytes(),before)
                self.assertEqual(cli.main(['--plan',str(src),'--output',str(root/'public.json')]),2)
                src.write_text('{bad');self.assertEqual(cli.main(['--plan',str(src),'--output',str(root/'private/new.json')]),2)


    def test_real_sg_cycle_and_self_loop(self):
        a=resource('aws_security_group',{'id':'sg-a','ingress':[{'security_groups':['sg-b','sg-a']}]},'a')
        b=resource('aws_security_group',{'id':'sg-b','ingress':[{'security_groups':['sg-a']}]},'b')
        r=g.build(minimal([a,b]))
        edges=[e for e in r['edges'] if e['relationship']=='INGRESS_REFERENCES_SECURITY_GROUP']
        self.assertEqual(len(edges),3);self.assertTrue(any(e['source']==e['target'] for e in edges))
        self.assertEqual(serialize(r),serialize(g.build(minimal([b,a]))))

    def test_unknown_inline_reference_is_not_proven(self):
        p=connected();row(p,'aws_security_group')['values']['ingress'][0]['security_groups']=['sg-fixture']
        mask(p,'aws_security_group',{'ingress':[{'security_groups':True}]})
        r=g.build(p);self.assertTrue(any(u['relationship']=='INGRESS_REFERENCES_SECURITY_GROUP' for u in r['unresolved']))
        self.assertFalse(any(e['relationship']=='INGRESS_REFERENCES_SECURITY_GROUP' for e in r['edges']))

    def test_names_identical_across_types_are_not_interchangeable(self):
        p=connected();row(p,'aws_iam_role')['values']['name']='sg-fixture'
        self.assertEqual(sum(e['relationship']=='USES_SECURITY_GROUP' for e in g.build(p)['edges']),1)


    def test_absolute_node_paths_rejected(self):
        for address in ['/private/source.tf','C:/private/source.tf']:
            p=connected();row(p,'aws_instance')['address']=address
            with self.assertRaises(ValueError):g.build(p)

    def test_malformed_inline_reference_list_rejected(self):
        p=connected();row(p,'aws_security_group')['values']['ingress'][0]['security_groups']=''
        with self.assertRaises(ValueError):g.build(p)


def add_relation(name,source_type,field,target_type,target_key,relation,reverse=False,many=False):
    def case(self):
        vals={field:['known'] if many else 'known'}
        if '.' in field:vals={field.split('.')[0]:[{'security_groups':['known']}]}
        p=minimal([resource(source_type,vals,'source'),resource(target_type,{target_key:'known'},'target')])
        r=g.build(p);matches=[e for e in r['edges'] if e['relationship']==relation]
        self.assertEqual(len(matches),1)
        self.assertEqual(matches[0]['source'],target_type+'.target' if reverse else source_type+'.source')
    setattr(GraphTests,'test_relation_'+name,case)
for source,specs in g.SPECS.items():
    for field,targets,keys,relation,reverse,many,_ in specs:
        add_relation(source+'_'+field,source,field,targets[0],keys[0],relation,reverse,many)
