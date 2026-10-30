"""Run fixed local synthetic fixtures; no real plan, cloud or AI access."""
import argparse
from pathlib import Path
import sys
from cloudguard.ci_fixtures import verify
from cloudguard.runtime import ROOT


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-output-dir',type=Path,default=ROOT/'reports/private/ci-phase4')
    parser.add_argument('--sanitized-output-dir',type=Path,default=ROOT/'reports/sanitized/ci-phase4')
    args=parser.parse_args(argv)
    try:verify(args.private_output_dir,args.sanitized_output_dir)
    except Exception:
        print('Phase 4 synthetic CI validation: FAIL; values withheld.',file=sys.stderr);return 2
    print('Phase 4 synthetic CI validation: PASS; context UNKNOWN, no runtime claims.');return 0


if __name__=='__main__':raise SystemExit(main())
