"""Operator-only provisioning/revocation. Never initialize from a workflow."""
import argparse
import json
import os
from pathlib import Path
from cloudguard.authorization import Ledger, require
from cloudguard.runtime import ROOT

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['initialize','revoke']);p.add_argument('--ledger',type=Path,required=True)
    p.add_argument('--approval-record',type=Path);p.add_argument('--confirm-separate-owner-approval',action='store_true')
    a=p.parse_args()
    try:
        require(not os.environ.get('GITHUB_ACTIONS') and a.confirm_separate_owner_approval)
        require(a.ledger.is_absolute() and not a.ledger.resolve().is_relative_to(ROOT))
        ledger=Ledger(a.ledger)
        if a.action=='initialize':
            require(a.approval_record is not None and a.approval_record.stat().st_size<=16384)
            ledger.initialize(json.loads(a.approval_record.read_text()))
        else:ledger.revoke()
        print('Operator ledger action completed; private values withheld')
    except Exception:
        print('Operator ledger action denied');raise SystemExit(1)
