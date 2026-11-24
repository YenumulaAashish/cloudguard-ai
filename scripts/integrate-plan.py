"""Explicit offline integration; never authenticate or execute Terraform."""
import argparse
from pathlib import Path
from cloudguard import phase5
from cloudguard.risk import read_document

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--checkov', type=Path, required=True)
    p.add_argument('--source', choices=['OFFLINE', 'SYNTHETIC'], default='OFFLINE')
    p.add_argument('--private-output', type=Path, required=True)
    p.add_argument('--public-output', type=Path, required=True)
    a = p.parse_args()
    try:
        phase5.publish(a.plan, a.private_output, a.public_output, a.source, [('checkov', read_document(a.checkov))])
    except Exception:
        print('Plan integration: FAIL; input/output values withheld.'); return 2
    print('Plan integration: PASS; source explicitly declared, context UNKNOWN.'); return 0

if __name__ == '__main__':
    raise SystemExit(main())
