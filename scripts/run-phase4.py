"""Integrate four explicit local reports; never run scanners or cloud commands."""
import argparse
from pathlib import Path
import sys
from cloudguard.posture import MAX_INPUT,publish
from cloudguard.risk import read_document
from cloudguard.runtime import ROOT


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for kind in ('iam','network','data','graph'):parser.add_argument('--'+kind+'-report',type=Path,required=True)
    parser.add_argument('--private-output-dir',type=Path,default=ROOT/'reports/private/phase4/integration')
    parser.add_argument('--sanitized-output-dir',type=Path,default=ROOT/'reports/sanitized/phase4')
    args=parser.parse_args(argv)
    try:
        reports={}
        for kind in ('iam','network','data','graph'):
            path=getattr(args,kind+'_report')
            if path.stat().st_size>MAX_INPUT:raise ValueError('Input size')
            reports[kind]=read_document(path)
        publish(reports,args.private_output_dir,args.sanitized_output_dir)
    except Exception:
        print('Phase 4 integration failed: invalid, inconsistent, oversized input or unavailable output. No completed run published.',file=sys.stderr)
        return 2
    print('Phase 4 integration completed; same-plan/freshness UNKNOWN, policy and risk authority unchanged.')
    return 0


if __name__=='__main__':raise SystemExit(main())
