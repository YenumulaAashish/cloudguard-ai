"""Validate the reviewed local CI contract; never trigger GitHub Actions."""
import argparse
import json
from pathlib import Path
from cloudguard.ci_security import verify
from cloudguard.runtime import ROOT


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    result=verify(parser.parse_args(argv).root)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['result']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
