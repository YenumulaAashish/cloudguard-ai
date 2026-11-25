"""Owner-operated loopback service. No AWS requests until authenticated explicit verification.
Do not install this service on a repository-controlled GitHub Actions runner.
"""
import argparse
import os
from pathlib import Path
import sys
from http.server import ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cloudguard.phase6.http import Service,handler
from cloudguard.phase6.engine import Engine
from cloudguard.phase6.config import require
from cloudguard_live.settings import load,Authority
from cloudguard_live.engine import LiveEngine

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=('mock','live'),default='mock');p.add_argument('--private-dir',required=True);p.add_argument('--configuration');p.add_argument('--authorization');p.add_argument('--prices');a=p.parse_args()
    folder=Path(a.private_dir).resolve();root=Path(__file__).resolve().parents[1]
    require(not folder.is_relative_to(root),'STATE_OUTSIDE_REPOSITORY_REQUIRED');folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    # A second process must never reopen this workspace. Crashed workers require owner inspection.
    lock=folder/'service.lock';fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        os.write(fd,str(os.getpid()).encode())
        if a.mode=='live':
            require(all((a.configuration,a.authorization,a.prices)),'PRIVATE_LIVE_BINDINGS_REQUIRED')
            auth=Authority(load(a.configuration),a.authorization)
            engine=LiveEngine(folder/'live',auth,lambda:load(a.prices))
        else:engine=Engine(folder/'mock')
        service=Service(engine,os.environ.get('CLOUDGUARD_OPERATOR_TOKEN',''))
        ThreadingHTTPServer(('127.0.0.1',8790),handler(service)).serve_forever()
    finally:os.close(fd);lock.unlink(missing_ok=True)
if __name__=='__main__':main()
