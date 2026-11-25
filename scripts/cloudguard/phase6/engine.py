"""Single-operator mock control plane. No AWS SDK, native deployment or role reuse."""
from copy import deepcopy
from decimal import Decimal
import json
import hashlib
from pathlib import Path
import time
import uuid
import re
from .config import validate,generate,render_hcl,mock_plan,digest,canonical,require,TEMPLATE_VERSION
from .cost import estimate
from .drift import detect
from .store import Store
from .gates import ToolGates,MANDATORY
from ..runtime import ROOT
from ..evidence import fingerprint

RESOURCE_TYPES={'aws_vpc','aws_subnet','aws_security_group','aws_default_security_group','aws_route_table','aws_route_table_association','aws_instance','aws_s3_bucket','aws_s3_bucket_public_access_block','aws_s3_bucket_server_side_encryption_configuration','aws_s3_bucket_versioning','aws_s3_bucket_ownership_controls','aws_s3_bucket_lifecycle_configuration','aws_s3_bucket_policy'}

class Engine:
    mode='MOCK_ONLY'
    def __init__(self,folder,runner=None,clock=time.time,source=fingerprint,cap='20.00',prices=None,fault_after=None):
        require(type(cap) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,3})\.[0-9]{2}',cap) and Decimal(cap)>0,'BUDGET_INVALID')
        self.store=Store(folder,clock);self.runner=runner or ToolGates();self.clock=clock;self.source=source;self.cap=cap
        self.prices=prices or ROOT/'security/phase6-mock-prices.json';self.fault_after=fault_after
    def catalog(self):return json.loads(Path(self.prices).read_text())
    def snapshot(self,s):return {'complete':s['complete'],'lineage':s['lineage'],'serial':s['serial'],'captured_at':self.clock(),'resources':s['observed']}
    def report(self,s):return detect(s['declared'],self.snapshot(s),s['lineage'],s['serial'],self.clock())
    def clean_observed(self,s):return {a:{'type':r['type'],'values':r['values']} for a,r in s['observed'].items()}
    def public_job(self,job,status,state=None):
        eligible=status=='READY' and job['created_at']<=self.clock()<job['expires_at'] and job['source']==self.source() and job['cap']==self.cap
        if state is not None:eligible=eligible and state['active_job'] is None and state['complete'] and state['serial']==job['serial'] and state['observed_revision']==job['observed_revision']
        try:eligible=eligible and estimate(job['config'],self.catalog(),self.cap,self.clock())==job['cost']
        except Exception:eligible=False
        try:eligible=eligible and all(hashlib.sha256((self.store.folder/job['id']/n).read_bytes()).hexdigest()==h for n,h in job['hashes'].items())
        except Exception:eligible=False
        value={k:deepcopy(job[k]) for k in ('id','purpose','mode','changes','gates','created_at','expires_at','confirmation','context_reason')}
        value['cost']={k:deepcopy(v) for k,v in job['cost'].items() if k in ('status','estimate_usd','limit_usd','mode','reason','expires_at')}
        return dict(value,kind='JOB',status=status,can_deploy=bool(eligible))
    def preview(self,config,purpose='CONFIG'):
        require(purpose in ('CONFIG','RECONCILE','DELETE','RECOVERY'),'INVALID_ACTION')
        c=validate(config);tf,target=generate(c);now=self.clock()
        with self.store.transaction() as (db,s):
            baseline=deepcopy(s);require(s['active_job'] is None,'WORKSPACE_BUSY')
        drift=self.report(baseline)
        jid=str(uuid.uuid4());folder=self.store.folder/jid;folder.mkdir(mode=0o700)
        plan=mock_plan(target,self.clean_observed(baseline))
        (folder/'main.tf').write_text(render_hcl(tf));(folder/'mock-plan.json').write_text(canonical(plan))
        initial={n:hashlib.sha256((folder/n).read_bytes()).hexdigest() for n in ('main.tf','mock-plan.json')}
        start_source=self.source()
        gates=self.runner.run(folder)
        require(self.source()==start_source and all(hashlib.sha256((folder/n).read_bytes()).hexdigest()==h for n,h in initial.items()),'GATE_INPUT_CHANGED')
        require(type(gates) is dict and set(gates)==set(MANDATORY)-{'cost'},'INVALID_GATE_EVIDENCE')
        for gate in gates.values():require(type(gate) is dict and gate.get('status') in ('PASS','FAIL','UNKNOWN','NOT_RUN'),'INVALID_GATE_EVIDENCE')
        try:cost=estimate(c,self.catalog(),self.cap,now)
        except Exception:cost={'status':'UNKNOWN','mode':'MOCK_ONLY','reason':'COST_UNKNOWN_OR_STALE','estimate_usd':None,'limit_usd':self.cap}
        gates['cost']={'status':cost['status'],'reason':cost['reason']}
        context='KNOWN_MOCK_CONTEXT'
        if not baseline['complete']:context='OBSERVATION_UNKNOWN'
        elif purpose=='CONFIG' and drift['status']!='IN_SYNC':context='DRIFT_REQUIRES_RECONCILIATION'
        elif any(not r.get('owned') for r in baseline['observed'].values()):context='UNMANAGED_RESOURCES'
        elif purpose=='RECONCILE' and drift['status']=='UNKNOWN':context='DRIFT_UNKNOWN'
        if purpose=='DELETE' and any(r.get('objects',0)>0 for r in baseline['observed'].values()):context='DATA_RETENTION_REVIEW'
        changes={'create':0,'update':0,'delete':0}
        for r in plan['resource_changes']:
            for action in r['change']['actions']:
                if action in changes:changes[action]+=1
        if changes['delete'] and any(r.get('objects',0)>0 for r in baseline['observed'].values()):context='DATA_RETENTION_REVIEW'
        confirmation='DELETE '+str(changes['delete'])+' MOCK RESOURCES' if changes['delete'] else ''
        status='READY' if all(g['status']=='PASS' for g in gates.values()) and context=='KNOWN_MOCK_CONTEXT' else 'BLOCKED'
        evidence={'gates':gates,'source':self.source(),'template':TEMPLATE_VERSION,'mode':'MOCK_ONLY'}
        (folder/'gate-evidence.json').write_text(canonical(evidence))
        hashes={name:hashlib.sha256((folder/name).read_bytes()).hexdigest() for name in ('main.tf','mock-plan.json','gate-evidence.json')}
        job={'id':jid,'purpose':purpose,'mode':'MOCK_ONLY','config':c,'target':target,'gates':gates,'cost':cost,'created_at':now,'expires_at':now+600,
          'source':self.source(),'template':TEMPLATE_VERSION,'hashes':hashes,'lineage':baseline['lineage'],'serial':baseline['serial'],
          'observed_revision':baseline['observed_revision'],'observed_digest':digest(baseline['observed']),'changes':changes,'confirmation':confirmation,'context_reason':context,'cap':self.cap}
        with self.store.transaction() as (db,s):
            require(s['serial']==baseline['serial'] and s['observed_revision']==baseline['observed_revision'],'STALE_PREVIEW')
            require(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]<1000,'HISTORY_CAPACITY')
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,NULL)',(jid,canonical(job),digest(job),status));self.store.save(db,s,'PLAN_PREVIEW',jid,digest(job))
        return self.public_job(job,status)
    def execute(self,jid,confirmation,request_id):
        require(str(uuid.UUID(request_id))==request_id,'INVALID_REQUEST_ID')
        with self.store.transaction() as (db,s):
            j,status,previous=self.store.job(db,jid)
            if previous==request_id and status in ('MOCK_SUCCEEDED','RECOVERY_REQUIRED'):return self.public_job(j,status)
            require(status=='READY' and previous is None,'PLAN_ALREADY_CONSUMED')
            require(s['active_job'] is None,'WORKSPACE_BUSY')
            require(j['lineage']==s['lineage'] and j['serial']==s['serial'] and j['observed_revision']==s['observed_revision'] and j['observed_digest']==digest(s['observed']),'STALE_STATE')
            require(j['created_at']<=self.clock()<j['expires_at'] and j['source']==self.source() and j['cap']==self.cap,'STALE_PLAN')
            require(j['mode']=='MOCK_ONLY' and all(j['gates'][k]['status']=='PASS' for k in MANDATORY) and j['context_reason']=='KNOWN_MOCK_CONTEXT','GATES_BLOCKED')
            require(confirmation==j['confirmation'],'DELETE_CONFIRMATION_REQUIRED')
            if j['changes']['delete']:require(not any(r.get('objects',0)>0 for r in s['observed'].values()),'DATA_RETENTION_REVIEW')
            require(s['complete'] and all(r.get('owned') for r in s['observed'].values()),'OBSERVATION_UNKNOWN')
            current=estimate(j['config'],self.catalog(),self.cap,self.clock())
            require(current==j['cost'] and current['status']=='PASS','COST_CHANGED_OR_STALE')
            folder=self.store.folder/jid
            require(all(hashlib.sha256((folder/n).read_bytes()).hexdigest()==h for n,h in j['hashes'].items()),'ARTIFACT_INTEGRITY')
            db.execute('UPDATE jobs SET status=?,request_id=? WHERE id=?',('EXECUTING',request_id,jid))
            s['active_job']={'id':jid,'lease_until':self.clock()+30};self.store.save(db,s,'DEPLOY_ACTION_AUTHORIZED_EXACT_MOCK_PLAN',jid)
        # Only in-memory/local SQLite mutations. No external execution adapter exists.
        with self.store.transaction() as (db,s):
            require(s['active_job'] and s['active_job']['id']==jid and self.clock()<s['active_job']['lease_until'],'EXECUTION_LEASE_LOST')
            observed=deepcopy(s['observed']);failed=False;steps=0
            for address in sorted(set(observed)|set(j['target'])):
                if self.fault_after is not None and steps>=self.fault_after:failed=True;break
                if address in j['target']:observed[address]=deepcopy(j['target'][address])|{'owned':True}
                else:observed.pop(address,None)
                steps+=1
            s['observed']=observed;s['observed_revision']+=1;s['active_job']=None
            status='RECOVERY_REQUIRED' if failed else 'MOCK_SUCCEEDED'
            if not failed:
                s['desired']=j['config'];s['declared']=j['target'];s['serial']+=1
            for address in set(observed)|set(s['declared']):s['inventory_ids'].setdefault(address,str(uuid.uuid4()))
            db.execute('UPDATE jobs SET status=? WHERE id=?',(status,jid));self.store.save(db,s,status,jid)
        self.drift()
        return self.public_job(j,status)
    def drift(self):
        with self.store.transaction() as (db,s):
            report=self.report(s);key=digest({'report':report,'serial':s['serial'],'observation':s['observed_revision']})
            if report['status']=='IN_SYNC':
                for a in s['alerts']:a['status']='RESOLVED'
            elif not any(a['key']==key for a in s['alerts']):
                s['alerts'].append({'id':str(uuid.uuid4()),'key':key,'status':'OPEN','kind':report['status']});s['alerts']=s['alerts'][-100:]
            self.store.save(db,s,'DRIFT_SCAN')
            rows=[]
            for r in report['changes']:
                s_id=s['inventory_ids'].get(r['address']) or 'unmanaged'
                rows.append({'resource_id':s_id,'resource_type':r['type'] if r['type'] in RESOURCE_TYPES else 'unsupported','kind':r['kind'],'fields':r['fields']})
            return {'kind':'DRIFT','mode':'MOCK_ONLY','status':report['status'],'reason':report['reason'],'changes':rows,'alerts':[{k:a[k] for k in ('id','kind','status')} for a in s['alerts']]}
    def reconcile(self):
        with self.store.transaction() as (db,s):require(s['desired'] is not None,'NO_DECLARED_CONFIGURATION');c=s['desired']
        return self.preview(c,'RECONCILE')
    def delete_preview(self):
        with self.store.transaction() as (db,s):require(s['desired'] is not None,'NO_DECLARED_CONFIGURATION');c=deepcopy(s['desired'])
        for k in ('vpc','ec2','s3'):c[k]['enabled']=False
        return self.preview(c,'DELETE')
    def recover(self,jid):
        with self.store.transaction() as (db,s):
            j,status,_=self.store.job(db,jid)
            if status=='EXECUTING':
                require(s['active_job'] and s['active_job']['id']==jid and self.clock()>=s['active_job']['lease_until'],'WORKSPACE_BUSY')
                s['active_job']=None;db.execute('UPDATE jobs SET status=? WHERE id=?',('RECOVERY_REQUIRED',jid));self.store.save(db,s,'INTERRUPTED_MOCK_JOB_ACKNOWLEDGED',jid)
            else:require(status=='RECOVERY_REQUIRED','RECOVERY_NOT_REQUIRED')
        return self.preview(j['config'],'RECOVERY')
    def simulate(self,scenario):
        require(scenario in ('CHANGE_CONTROL','RESOURCE_MISSING','OBSERVATION_UNAVAILABLE','OBSERVATION_AVAILABLE'),'INVALID_SCENARIO')
        with self.store.transaction() as (db,s):
            require(s['active_job'] is None,'WORKSPACE_BUSY')
            if scenario.startswith('OBSERVATION_'):s['complete']=scenario=='OBSERVATION_AVAILABLE'
            else:
                require(bool(s['observed']),'NO_MOCK_RESOURCES');address=sorted(s['observed'])[0]
                if scenario=='RESOURCE_MISSING':s['observed'].pop(address)
                else:s['observed'][address]['values']['tags']={'ManagedBy':'ChangedByMockScenario'}
            s['observed_revision']+=1;self.store.save(db,s,'MOCK_DRIFT_SCENARIO')
        return self.drift()
    def status(self):
        with self.store.transaction() as (db,s):
            inventory=[{'id':s['inventory_ids'].get(a,'unmanaged'),'resource_type':r['type'] if r['type'] in RESOURCE_TYPES else 'unsupported','status':'OBSERVED_MOCK' if s['complete'] else 'UNKNOWN','owned':r.get('owned') is True} for a,r in sorted(s['observed'].items())]
            jobs=[self.public_job(json.loads(p),status,s) for p,status in db.execute('SELECT payload,status FROM jobs ORDER BY rowid DESC LIMIT 30')]
            audit=[{'sequence':r['seq'],'kind':r['kind'],'job':r['job'],'serial':r['serial'],'recorded_at':r['recorded_at']} for (p,) in db.execute('SELECT payload FROM audit ORDER BY seq DESC LIMIT 30') for r in [json.loads(p)]]
            return {'kind':'STATUS','mode':'MOCK_ONLY','inventory':inventory,'history':jobs,'audit':audit,'state_serial':s['serial'],'busy':s['active_job'] is not None,'budget_limit_usd':self.cap}
