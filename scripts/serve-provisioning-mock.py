"""Start only the isolated loopback mock control plane. No AWS mode exists."""
import argparse
import os
from pathlib import Path
from http.server import ThreadingHTTPServer
from cloudguard.runtime import PRIVATE
from cloudguard.phase6.engine import Engine
from cloudguard.phase6.http import Service,handler

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--budget-limit-usd',default='20.00');a=p.parse_args()
    os.umask(0o077)
    try:
        secret=os.environ.get('CLOUDGUARD_OPERATOR_TOKEN','')
        if not 32<=len(secret)<=128:raise ValueError('Operator secret required')
        engine=Engine(PRIVATE/'phase6-mock',cap=a.budget_limit_usd)
        server=ThreadingHTTPServer(('127.0.0.1',8790),handler(Service(engine,secret)))
        print('MOCK ONLY on loopback 8790. No AWS deployment capability. Operator secret is not logged.')
        server.serve_forever()
    except KeyboardInterrupt:return 0
    except Exception:print('Mock control plane unavailable; values withheld.');return 1
if __name__=='__main__':raise SystemExit(main())
