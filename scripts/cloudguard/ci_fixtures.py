"""Explicit synthetic Phase 4 smoke check; outputs remain ephemeral in CI."""
from . import iam,network,data_protection,security_graph,posture
from .findings import serialize
from .risk import read_document
from .runtime import ROOT


def reports(plan):
    result={'iam':iam.analyze(plan),'network':network.analyze(plan),'data':data_protection.analyze(plan)}
    result['graph']=security_graph.build(plan,result)
    return result


def verify(private_dir,public_dir):
    plan=read_document(ROOT/'tests/fixtures/graph/connected.json')
    first=reports(plan)
    if serialize(first)!=serialize(reports(plan)):raise ValueError('Fixture reproduction failed')
    return posture.publish(first,private_dir,public_dir)
