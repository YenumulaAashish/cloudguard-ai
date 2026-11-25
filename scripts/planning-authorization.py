"""Trusted dedicated-runner ledger gate; fixed diagnostics, no implicit grant creation."""
import argparse
import json
import os
from pathlib import Path
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from cloudguard.authorization import Ledger, context, require, REPOSITORY
from cloudguard.runtime import ROOT, REPORTS
from cloudguard.evidence import context as evidence_context, load, fingerprint

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('PLANNING_AUTHORIZATION_DENIED')

def github_evidence(env, get=None, allow_self_review=False):
    def request(path):
        token=env.get('GH_TOKEN');require(token)
        req=Request('https://api.github.com/repos/'+REPOSITORY+path,headers={
            'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with build_opener(ProxyHandler({}),NoRedirect()).open(req,timeout=15) as r:
            raw=r.read(131073);require(len(raw)<=131072);return json.loads(raw)
    get=get or request
    branch=get('/branches/main')
    require(branch.get('protected') is True and branch['commit']['sha']==env['GITHUB_SHA'])
    reviews=get('/actions/runs/'+env['GITHUB_RUN_ID']+'/approvals')
    require(type(reviews) is list)
    relevant=[r for r in reviews if any(e.get('name')=='aws-plan' for e in r.get('environments',[]))]
    require(not any(r.get('state')=='rejected' for r in relevant))
    actor=env.get('GITHUB_TRIGGERING_ACTOR') or env.get('GITHUB_ACTOR')
    require(type(actor) is str and 0<len(actor)<=100)
    require(any(r.get('state')=='approved' and r.get('user',{}).get('type')=='User' and
                type(r.get('user',{}).get('login')) is str and
                (allow_self_review is True or r['user']['login'].casefold()!=actor.casefold()) for r in relevant))

def gate(env):
    ctx=evidence_context();require(ctx['source_digest']==fingerprint())
    require(all(load(n).get('result')=='PASS' for n in ('checks','checkov','checkov-exceptions','policy-tests','ci-safety')))
    require(0<=time.time()-__import__('datetime').datetime.fromisoformat(ctx['started_at']).timestamp()<=1800)
    env=dict(env,CLOUDGUARD_SOURCE_DIGEST=ctx['source_digest']);scope=context(env)
    raw=Path(env['CLOUDGUARD_LEDGER_PATH']);require(raw.is_absolute())
    path=raw.resolve();require(not path.is_relative_to(ROOT) and not raw.is_symlink())
    require(env.get('AWS_PLAN_ENABLED')=='true' and env.get('AWS_PLAN_REVIEW_APPROVED')=='true')
    ledger=Ledger(path);grant=ledger.approved_grant();require(scope==grant['scope'])
    github_evidence(env,allow_self_review=grant['allow_self_review'])
    return ledger,scope

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['reserve','start','finish']);a=p.parse_args()
    os.umask(0o077)
    receipt=ROOT/'reports/private/planning-reservation.json'
    try:
        env=os.environ;run=env['GITHUB_RUN_ID'];now=time.time()
        if a.action=='reserve':
            ledger,scope=gate(env);require(not receipt.exists())
            nonce=ledger.reserve(run,scope,time.time())
            receipt.parent.mkdir(parents=True,exist_ok=True)
            with receipt.open('x') as f:json.dump({'run_id':run,'nonce':nonce},f)
        elif a.action=='start':
            ledger,scope=gate(env);r=json.loads(receipt.read_text());require(r['run_id']==run)
            deadline=ledger.transition(run,r['nonce'],'STARTED',time.time(),scope)
            r['deadline']=deadline
            receipt.write_text(json.dumps(r))
        else:
            if not receipt.exists():return 0
            raw=Path(env['CLOUDGUARD_LEDGER_PATH']);require(raw.is_absolute() and not raw.resolve().is_relative_to(ROOT))
            r=json.loads(receipt.read_text());require(r['run_id']==run)
            status={'success':'COMPLETE','failure':'FAILED','cancelled':'CANCELLED'}[env['CI_JOB_STATUS']]
            Ledger(raw).transition(run,r['nonce'],status,now)
        print('Planning authorization: PASS; private ledger values withheld');return 0
    except Exception:
        print('Planning authorization: DENIED; operator review required');return 1

if __name__=='__main__':raise SystemExit(main())
