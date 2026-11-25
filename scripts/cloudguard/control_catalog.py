"""Reviewed static context only. Never derive provider prose from imported values."""
from copy import deepcopy
import json
from .runtime import ROOT

def describe(control,domain):
    value=json.loads((ROOT/'security/control-descriptions.json').read_text())
    row=value['controls'].get(control)
    if row is None or row['domain']!=domain:raise ValueError('Unsupported advisory control')
    return deepcopy(row)
