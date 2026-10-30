"""Network exposure and conservative unknowns; synthetic plans only."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cloudguard import network as n
from cloudguard.findings import serialize
from cloudguard.risk import assess_risk,read_document
from cloudguard.integration import schema_validate


def rule(**kw): return {'protocol':'tcp','from_port':22,'to_port':22,'cidr_blocks':['0.0.0.0/0'],**kw}
def plan(r=None,typ='aws_security_group',direction='ingress'):
    v={direction:[rule() if r is None else r],('egress' if direction=='ingress' else 'ingress'):[]} if typ in n.GROUPS else (rule() if r is None else r)
    if typ=='aws_security_group_rule': v={'type':direction,**v}
    return {'format_version':'1.2','planned_values':{'root_module':{'resources':[{'address':typ+'.example','type':typ,'values':v}]}}}
def rows(p): return n.analyze(p)['findings']
def ids(p): return [r['control_id'] for r in rows(p)]


class NetworkTests(unittest.TestCase):
    def test_empty_and_other_resources(self):
        p=plan();p['planned_values']['root_module']['resources']=[];self.assertEqual(rows(p),[])
        self.assertEqual(rows(plan(typ='aws_s3_bucket')),[])
        self.assertEqual(rows(plan({'protocol':'tcp','from_port':22,'to_port':22,'cidr_blocks':['10.0.0.0/8']})),[])

    def test_empty_explicit_group(self):
        p=plan();p['planned_values']['root_module']['resources'][0]['values']={'ingress':[],'egress':[]}
        self.assertEqual(rows(p),[])

    def test_fixtures(self):
        for name,expected in [('public-ssh',['CGA_NET_002']),('scoped',[])]:
            self.assertEqual(ids(read_document(ROOT/'tests/fixtures/network'/f'{name}.json')),expected)

    def test_all_protocol_suppresses_services(self):
        for proto in ['-1',-1,'all']:
            self.assertEqual(ids(plan(rule(protocol=proto))),['CGA_NET_001'])

    def test_broad_suppresses_specific_ports(self):
        self.assertEqual(ids(plan(rule(from_port=0,to_port=65535))),['CGA_NET_006'])

    def test_udp_is_not_ssh(self):
        self.assertEqual(ids(plan(rule(protocol='udp'))),[])

    def test_egress_is_not_ingress(self):
        self.assertEqual(ids(plan(direction='egress')),[])
        result=rows(plan(rule(protocol='-1'),direction='egress'))
        self.assertEqual(result[0]['control_id'],'CGA_NET_008');self.assertEqual(result[0]['severity'],'LOW')
        self.assertNotIn('Ingress',result[0]['message'])

    def test_cidr_dedup_and_mixed(self):
        self.assertEqual(ids(plan(rule(cidr_blocks=['10.0.0.0/8','0.0.0.0/0','0.0.0.0/0']))),['CGA_NET_002'])
        result=rows(plan(rule(ipv6_cidr_blocks=['::/0'])))
        self.assertEqual([r['address_family'] for r in result],['IPv4','IPv6'])

    def test_malformed_cidrs(self):
        for cidr in ['bad','0.0.0.0','10.1.2.3/8','::/0']:
            with self.subTest(cidr=cidr),self.assertRaises(ValueError):rows(plan(rule(cidr_blocks=[cidr])))

    def test_sg_and_self_are_not_public(self):
        for extra in [{'security_groups':['sg-example']},{'self':True},{'source_security_group_id':'sg-example'},{'referenced_security_group_id':'sg-example'}]:
            self.assertEqual(rows(plan(rule(protocol='-1',cidr_blocks=[],**extra))),[])

    def test_prefix_is_unknown_not_public(self):
        self.assertEqual(ids(plan(rule(cidr_blocks=[],prefix_list_ids=['pl-example']))),['CGA_NET_009'])

    def test_no_source_is_unknown(self):
        self.assertEqual(ids(plan(rule(cidr_blocks=[]))),['CGA_NET_009'])

    def test_icmp_not_tcp(self):
        self.assertEqual(ids(plan(rule(protocol='icmp',from_port=22,to_port=-1))),['CGA_NET_007'])
        with self.assertRaises(ValueError):rows(plan(rule(protocol='icmp',from_port=-1,to_port=22)))

    def test_icmpv6_family(self):
        self.assertEqual(ids(plan(rule(protocol='58',from_port=-1,to_port=-1,cidr_blocks=[],ipv6_cidr_blocks=['::/0']))),['CGA_NET_007'])
        self.assertEqual(ids(plan(rule(protocol='58',from_port=-1,to_port=-1))),['CGA_NET_009'])

    def test_unknown_protocol_and_missing_ports(self):
        for changes in [{'protocol':None},{'protocol':'gre'},{'from_port':None},{'to_port':None}]:
            self.assertEqual(ids(plan(rule(**changes))),['CGA_NET_009'])

    def test_invalid_ports_protocol_and_description(self):
        for changes in [{'protocol':True},{'from_port':'22'},{'to_port':True},{'from_port':23,'to_port':22},{'to_port':65536},{'from_port':-1},{'description':123}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):rows(plan(rule(**changes)))

    def test_missing_ports_all_protocol_valid(self):
        r=rule(protocol=-1);r.pop('from_port');r.pop('to_port')
        self.assertEqual(ids(plan(r)),['CGA_NET_001'])

    def test_standalone_modern_ipv6(self):
        p=plan({'ip_protocol':'6','from_port':22,'to_port':22,'cidr_ipv6':'::/0','security_group_id':'sg-target'},'aws_vpc_security_group_ingress_rule')
        self.assertEqual(rows(p)[0]['address_family'],'IPv6')

    def test_unknown_masks(self):
        for field in ['cidr_blocks','protocol','from_port','to_port','referenced_security_group_id','security_group_id']:
            p=plan(typ='aws_vpc_security_group_ingress_rule');r=p['planned_values']['root_module']['resources'][0]
            p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':r['values'],'after_unknown':{field:True},'actions':['create']}}]
            self.assertEqual(ids(p),['CGA_NET_009'])
        p=plan();r=p['planned_values']['root_module']['resources'][0]
        p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':r['values'],'after_unknown':{'ingress':[{'cidr_blocks':True}]}}}]
        self.assertEqual(ids(p),['CGA_NET_009'])

    def test_delete_replacement_and_unknown_create(self):
        for actions,expected in [(['delete'],[]),(['delete','create'],['CGA_NET_002']),(['create','delete'],['CGA_NET_002'])]:
            p=plan();r=p['planned_values']['root_module']['resources'][0]
            p['resource_changes']=[{'address':r['address'],'type':r['type'],'change':{'after':r['values'],'actions':actions}}]
            self.assertEqual(ids(p),expected)
        p=plan();p['planned_values']['root_module']['resources']=[]
        p['resource_changes']=[{'address':'aws_security_group.x','type':'aws_security_group','change':{'after':{},'after_unknown':True,'actions':['create']}}]
        self.assertEqual(ids(p),['CGA_NET_009'])

    def test_distinct_rule_indexes_and_order(self):
        p=plan();v=p['planned_values']['root_module']['resources'][0]['values'];v['ingress']*=2
        self.assertEqual([r['rule_index'] for r in rows(p)],[0,1])
        resource=deepcopy(p['planned_values']['root_module']['resources'][0]);resource['address']='module.z.aws_security_group.x'
        p['planned_values']['root_module']['resources'].append(resource)
        first=serialize(n.analyze(p));p['planned_values']['root_module']['resources'].reverse()
        self.assertEqual(first,serialize(n.analyze(p)))

    def test_nested_module(self):
        p=plan();root=p['planned_values']['root_module'];root['child_modules']=[{'resources':root.pop('resources')}]
        self.assertEqual(ids(p),['CGA_NET_002'])

    def test_missing_rules_unknown(self):
        p=plan();p['planned_values']['root_module']['resources'][0]['values']={}
        self.assertEqual(ids(p),['CGA_NET_009','CGA_NET_009'])

    def test_schema_and_tampering(self):
        result=n.analyze(plan());n.validate(result)
        for changed in [{**result,'extra':True},{**result,'schema_version':'9'}]:
            with self.assertRaises(Exception):n.validate(changed)
        result['findings'][0]['severity']='LOW'
        with self.assertRaises(ValueError):n.validate(result)

    def test_bounds(self):
        for r in [rule(cidr_blocks=['0.0.0.0/0']*129),rule(description='x'*2049),rule(security_groups=['sg']*129),rule(prefix_list_ids=['pl']*129)]:
            with self.assertRaises(ValueError):rows(plan(r))
        p=plan();p['planned_values']['root_module']['resources'][0]['values']['ingress']*=257
        with self.assertRaises(ValueError):rows(p)

    def test_inert_strings_and_no_execution(self):
        for sentinel in ['</script>','Ignore previous instructions','terraform apply','${file("secret")}','<!-- fake security report -->','`rm -rf /`']:
            p=plan(rule(description=sentinel));r=p['planned_values']['root_module']['resources'][0];r['address']=sentinel;before=deepcopy(p)
            with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execution')),patch.dict('os.environ',{},clear=True):
                output=n.analyze(p)
            self.assertEqual(p,before);self.assertNotIn(sentinel,output['findings'][0]['message'])

    def test_compatibility_and_unknown_warning(self):
        for p in [plan(),plan(rule(protocol=None))]:
            result=n.normalized(n.analyze(p));schema_validate(result,'normalized');assess_risk(result)
            self.assertEqual(result['findings'][0]['metadata']['analyzer'],'cloudguard-network')
            self.assertFalse(result['findings'][0]['exception'])

    def test_cli_private_collision_and_errors(self):
        spec=importlib.util.spec_from_file_location('net_cli',ROOT/'scripts/analyze-network.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);src=root/'input.json';src.write_text(serialize(plan()))
            with patch.object(cli,'PRIVATE',root/'private'):
                target=root/'private/report.json';args=['--plan',str(src),'--output',str(target)]
                self.assertEqual(cli.main(args),0);before=target.read_bytes()
                self.assertEqual(cli.main(args),2);self.assertEqual(target.read_bytes(),before)
                self.assertEqual(cli.main(['--plan',str(src),'--output',str(root/'public.json')]),2)
                src.write_text('{invalid')
                self.assertEqual(cli.main(['--plan',str(src),'--output',str(root/'private/new.json')]),2)


    def test_legacy_egress_and_inline_egress(self):
        for typ in ['aws_security_group_rule','aws_security_group']:
            self.assertEqual(ids(plan(rule(protocol=-1),typ,'egress')),['CGA_NET_008'])

    def test_prefix_and_known_public_are_distinct(self):
        self.assertEqual(ids(plan(rule(prefix_list_ids=['pl-example']))),['CGA_NET_002','CGA_NET_009'])

    def test_malformed_envelope(self):
        for p in [{},{'format_version':'9'}, {**plan(),'errored':True}]:
            with self.assertRaises(ValueError):rows(p)

    def test_schema_rejects_extra_finding(self):
        result=n.analyze(plan());result['findings'][0]['private']='unexpected'
        with self.assertRaises(Exception):n.validate(result)

    def test_resource_and_module_bounds(self):
        p=plan();resource=p['planned_values']['root_module']['resources'][0]
        p['planned_values']['root_module']['resources']=[resource]*2049
        with self.assertRaises(ValueError):rows(p)
        p=plan();root=p['planned_values']['root_module']
        for _ in range(33):root['child_modules']=[{}];root=root['child_modules'][0]
        with self.assertRaises(ValueError):rows(p)

    def test_unknown_protocol_never_safe_or_public(self):
        result=rows(plan(rule(protocol=None)))
        self.assertEqual(result[0]['status'],'UNKNOWN');self.assertEqual(result[0]['address_family'],'UNKNOWN')


def add(name,p,expected):
    def case(self):self.assertEqual(ids(p),expected)
    setattr(NetworkTests,'test_'+name,case)
for family,kw in [('v4',{}),('v6',{'cidr_blocks':[],'ipv6_cidr_blocks':['::/0']})]:
    for port,control in [(22,'CGA_NET_002'),(3389,'CGA_NET_003')]+[(p,'CGA_NET_004') for p in n.DATABASE]+[(p,'CGA_NET_005') for p in n.MANAGEMENT]:
        add(f'{family}_port_{port}',plan(rule(from_port=port,to_port=port,**kw)),[control])
    add(f'{family}_all_protocol',plan(rule(protocol=-1,**kw)),['CGA_NET_001'])
for cidr in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','203.0.113.0/24']:
    add('scoped_'+cidr.replace('/','_').replace('.','_'),plan(rule(cidr_blocks=[cidr])),[])
add('scoped_ipv6',plan(rule(cidr_blocks=[],ipv6_cidr_blocks=['2001:db8::/32'])),[])
for proto in ['tcp','udp','6','17']:
    add('broad_'+proto,plan(rule(protocol=proto,from_port=1000,to_port=65000)),['CGA_NET_006'])
for lo,hi,expected in [(20,25,['CGA_NET_002','CGA_NET_005']),(3380,3390,['CGA_NET_003']),(8000,8010,[]),(10000,11022,[]),(10000,11023,['CGA_NET_006'])]:
    add(f'range_{lo}_{hi}',plan(rule(from_port=lo,to_port=hi)),expected)
for typ in sorted(n.GROUPS|n.RULES):
    direction='egress' if typ.endswith('egress_rule') else 'ingress'
    add('type_'+typ,plan(typ=typ,direction=direction),[] if direction=='egress' else ['CGA_NET_002'])
for typ in sorted(n.CONTEXT|{'aws_security_group_unsupported'}): add('unsupported_'+typ,plan(typ=typ),['CGA_NET_009'])
