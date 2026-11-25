"""Native AWS engine. Default unverified; no process or SDK call occurs at construction."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading
import time
import uuid
from cloudguard.phase6.config import require,validate,generate,render_hcl,digest,canonical
from cloudguard.phase6.store import Store
from cloudguard.phase6.gates import ToolGates,MANDATORY
from cloudguard.phase6.engine import RESOURCE_TYPES
from .aws import AWS
from .native import Native
from .pricing import estimate
from .settings import source

ARTIFACTS=('main.tf','backend.json','.terraform.lock.hcl','validated.tfplan','tfplan.json','gate-evidence.json')
def hashes(folder):
    names=list(ARTIFACTS)
    if (folder/'deletion-security-source/main.tf').exists():names.append('deletion-security-source/main.tf')
    return {n:hashlib.sha256((folder/n).read_bytes()).hexdigest() for n in names}
def unknown(value):
    if isinstance(value,dict):return any(unknown(x) for x in value.values())
    if isinstance(value,list):return any(unknown(x) for x in value)
    return value is True

def plan_scope(plan):
    require(plan.get('format_version') in ('1.1','1.2') and plan.get('terraform_version')=='1.9.8','UNSUPPORTED_PLAN')
    changes={'create':0,'update':0,'delete':0}
    for r in plan.get('resource_changes',[]):
        require(r.get('mode')=='managed' and r.get('type') in RESOURCE_TYPES and r.get('address')==r['type']+'.this','PLAN_SCOPE_INVALID')
        actions=r['change']['actions'];require(actions in (['create'],['update'],['delete'],['no-op'],['delete','create'],['create','delete']),'PLAN_ACTION_INVALID')
        require(not r.get('previous_address') and not r.get('importing') and not r.get('change',{}).get('importing'),'STATE_IMPORT_DENIED')
        for a in actions:
            if a in changes:changes[a]+=1
    return changes

class LiveEngine:
    def __init__(self,folder,authority,price_loader,aws=None,native=None,gates=None,clock=time.time,source_fn=source):
        self.auth=authority;self.c=authority.c;self.clock=clock;self.source=source_fn;self.store=Store(folder,clock)
        self.aws=aws or AWS(authority);self.native=native or Native(authority,self.aws);self.gates=gates or ToolGates();self.price_loader=price_loader
        self.lock=threading.Lock();self.connected=False
    @property
    def mode(self):
        try:return 'LIVE_VERIFIED' if self.connected and self.aws.fresh() else 'LIVE_UNVERIFIED'
        except Exception:return 'LIVE_UNVERIFIED'
    def connectivity(self):
        self.connected=False
        try:r=self.aws.verify();self.connected=True;return r
        except Exception:return {'kind':'CONNECTION','status':'UNVERIFIED','reason':'LIVE_AUTHORIZATION_OR_SUPPORT_UNAVAILABLE','checked_at':0}
    def ready(self,op='plan'):
        require(self.mode=='LIVE_VERIFIED','EXPLICIT_CONNECTIVITY_VERIFICATION_REQUIRED')
        return self.auth.check(op)
    def public_job(self,j,status,s=None):
        eligible=False
        try:
            eligible=(status=='READY' and self.mode=='LIVE_VERIFIED' and self.auth.check('delete' if j['changes']['delete'] else 'deploy')==j['approval'] and j['source']==self.source() and j['created_at']<=self.clock()<j['expires_at'] and hashes(self.store.folder/j['id'])==j['hashes'] and estimate(j['config'],self.price_loader(),self.c,self.clock())==j['cost'])
            if s:eligible=eligible and s['active_job'] is None and (s['complete'] or j['purpose']=='RECOVERY') and j['revision']==s['observed_revision']
        except Exception:pass
        value={k:deepcopy(j[k]) for k in ('id','purpose','changes','gates','cost','confirmation','created_at','expires_at','context_reason')}
        return dict(value,kind='JOB',mode=self.mode,status=status,can_deploy=bool(eligible))
    def preview(self,configuration,purpose='CONFIG'):
        with self.lock:return self._preview(configuration,purpose)
    def _preview(self,configuration,purpose):
        approval=self.ready();c=validate(configuration)
        require(purpose in ('CONFIG','RECONCILE','DELETE','RECOVERY') and c['project']==self.c['project'],'EXACT_WORKSPACE_REQUIRED')
        with self.store.transaction() as (db,s):
            require(s['active_job'] is None,'WORKSPACE_BUSY')
            require(s['complete'] or purpose=='RECOVERY','RECOVERY_REQUIRED')
            revision=s['observed_revision']
        start=self.source();jid=str(uuid.uuid4());folder=self.store.folder/jid;folder.mkdir(mode=0o700)
        tf,target=generate(c,self.c['support']);self.native.prepare(folder,tf)
        if not target:
            with self.store.transaction() as (db,s):previous=deepcopy(s['desired'])
            require(previous is not None,'NO_DECLARED_CONFIGURATION')
            retained=folder/'deletion-security-source';retained.mkdir()
            (retained/'main.tf').write_text(render_hcl(generate(previous,self.c['support'])[0]),encoding='utf-8')
        baseline=self.native.state(folder);plan=self.native.plan(folder);changes=plan_scope(plan)
        require(self.native.state(folder)==baseline,'STATE_CHANGED_DURING_PLAN')
        inputs={n:hashlib.sha256((folder/n).read_bytes()).hexdigest() for n in (*ARTIFACTS,*(['deletion-security-source/main.tf'] if not target else [])) if n!='gate-evidence.json'}
        gates=self.gates.run(folder,native=True)
        require(type(gates) is dict and set(gates)==set(MANDATORY)-{'cost'},'INVALID_GATE_EVIDENCE')
        require(all(type(g) is dict and g.get('status') in ('PASS','FAIL','UNKNOWN','NOT_RUN') for g in gates.values()),'INVALID_GATE_EVIDENCE')
        cost=estimate(c,self.price_loader(),self.c,self.clock());gates['cost']={'status':cost['status'],'reason':cost['reason']}
        require(self.source()==start and self.auth.check('plan')==approval and all(hashlib.sha256((folder/n).read_bytes()).hexdigest()==h for n,h in inputs.items()),'GATE_INPUT_CHANGED')
        context='VERIFIED_LIVE_CONTEXT'
        try:
            inventory=self.aws.inventory({tuple(x) for x in baseline['managed']})
            if any(r.get('owned') is not True for r in inventory):context='UNMANAGED_RESOURCES'
        except Exception:context='OBSERVATION_UNKNOWN'
        drifts=plan.get('resource_drift',[])
        if context=='VERIFIED_LIVE_CONTEXT' and purpose=='CONFIG' and drifts:context='DRIFT_REQUIRES_RECONCILIATION'
        if any(unknown(r.get('change',{}).get('after_unknown',{})) for r in drifts):context='DRIFT_UNKNOWN'
        # ForceDestroy is permanently false; versioned objects and pending uploads block deletion.
        if changes['delete']:
            for r in plan.get('resource_changes',[]):
                if r['type']=='aws_s3_bucket' and 'delete' in r['change']['actions']:
                    try:self.aws.empty_bucket(r['change']['before']['bucket'])
                    except Exception:context='DATA_RETENTION_REVIEW'
        confirmation='DELETE '+str(changes['delete'])+' LIVE RESOURCES' if changes['delete'] else ''
        status='READY' if context=='VERIFIED_LIVE_CONTEXT' and all(g['status']=='PASS' for g in gates.values()) else 'BLOCKED'
        (folder/'gate-evidence.json').write_text(canonical({'gates':gates,'source':start,'approval':approval}),encoding='utf-8')
        now=self.clock();job={'id':jid,'purpose':purpose,'config':c,'changes':changes,'gates':gates,'cost':cost,'context_reason':context,'confirmation':confirmation,'created_at':now,'expires_at':now+600,'source':start,'approval':approval,'revision':revision,'baseline':baseline,'hashes':hashes(folder)}
        with self.store.transaction() as (db,s):
            require(s['active_job'] is None and s['observed_revision']==revision,'STALE_PREVIEW');require(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]<1000,'HISTORY_CAPACITY')
            s['native']=baseline;s['serial']=baseline['serial']
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,NULL)',(jid,canonical(job),digest(job),status));self.store.save(db,s,'PLAN_PREVIEW',jid,digest(job))
        return self.public_job(job,status)
    def execute(self,jid,confirmation,request_id):
        require(str(uuid.UUID(request_id))==request_id,'INVALID_REQUEST_ID')
        with self.lock:
            with self.store.transaction() as (db,s):
                j,status,previous=self.store.job(db,jid)
                if previous==request_id and status in ('SUCCEEDED','RECOVERY_REQUIRED'):return self.public_job(j,status)
                require(status=='READY' and previous is None and s['active_job'] is None,'PLAN_CONSUMED_OR_BUSY')
                recovery=j['purpose']=='RECOVERY' and j['revision']==s['observed_revision']
                require((s['complete'] or recovery) and j['revision']==s['observed_revision'],'STALE_WORKSPACE_GENERATION')
                eligibility_state=deepcopy(s);eligibility_state['complete']=True if recovery else s['complete']
                require(self.public_job(j,status,eligibility_state)['can_deploy'],'EXACT_VALIDATED_PLAN_REQUIRED')
                require(confirmation==j['confirmation'],'DELETE_CONFIRMATION_REQUIRED')
                self.ready('delete' if j['changes']['delete'] else 'deploy');folder=self.store.folder/jid
                require(self.native.state(folder)==j['baseline'],'STALE_REMOTE_STATE')
                plan=json.loads((folder/'tfplan.json').read_text(encoding='utf-8'))
                require(plan_scope(plan)==j['changes'],'PLAN_SCOPE_CHANGED')
                require(all(j['gates'][k]['status']=='PASS' for k in MANDATORY) and j['context_reason']=='VERIFIED_LIVE_CONTEXT','MANDATORY_GATES_BLOCKED')
                for r in plan.get('resource_changes',[]):
                    if r['type']=='aws_s3_bucket' and 'delete' in r['change']['actions']:self.aws.empty_bucket(r['change']['before']['bucket'])
                db.execute('UPDATE jobs SET status=?,request_id=? WHERE id=?',('EXECUTING',request_id,jid));s['active_job']={'id':jid};self.store.save(db,s,'OPERATOR_AUTHORIZED_EXACT_NATIVE_PLAN',jid)
            try:
                self.native.execute(folder,j['changes']['delete']>0);observed=self.native.state(folder);status='SUCCEEDED'
            except Exception:observed=None;status='RECOVERY_REQUIRED'
            with self.store.transaction() as (db,s):
                require(s['active_job']=={'id':jid},'EXECUTION_OWNERSHIP_LOST')
                s['active_job']=None;s['observed_revision']+=1;s['desired']=j['config'];s['complete']=observed is not None
                if observed is not None:s['serial']=observed['serial'];s['native']=observed
                db.execute('UPDATE jobs SET status=? WHERE id=?',(status,jid));self.store.save(db,s,status,jid)
            return self.public_job(j,status)
    def drift(self):
        with self.lock:
            self.ready()
            with self.store.transaction() as (db,s):
                require(s['active_job'] is None and s['desired'] is not None,'DECLARED_CONFIGURATION_REQUIRED');c=s['desired']
            folder=self.store.folder/str(uuid.uuid4());folder.mkdir(mode=0o700)
            result='UNKNOWN';rows=[]
            try:
                tf,_=generate(c,self.c['support']);self.native.prepare(folder,tf)
                baseline=self.native.state(folder);plan=self.native.plan(folder,refresh=True);plan_scope(plan)
                require(self.native.state(folder)==baseline,'STATE_CHANGED_DURING_DRIFT')
                drifts=plan.get('resource_drift',[])
                require(all(r.get('type') in RESOURCE_TYPES and r.get('address')==r['type']+'.this' for r in drifts),'DRIFT_SCOPE_UNKNOWN')
                require(not any(unknown(r.get('change',{}).get('after_unknown',{})) for r in drifts),'DRIFT_UNKNOWN')
                result='DRIFTED' if drifts else 'IN_SYNC'
                for r in drifts:
                    rows.append({'resource_id':str(uuid.uuid5(uuid.NAMESPACE_OID,r['address'])),'resource_type':r['type'],'kind':'MISSING' if r['change'].get('after') is None else 'CHANGED','fields':['CONFIGURATION']})
            except Exception:result='UNKNOWN'
            with self.store.transaction() as (db,s):
                if result=='IN_SYNC':
                    for a in s['alerts']:a['status']='RESOLVED'
                else:s['alerts']=(s['alerts']+[{'id':str(uuid.uuid4()),'kind':result,'status':'OPEN'}])[-100:]
                self.store.save(db,s,'LIVE_DRIFT_SCAN');alerts=deepcopy(s['alerts'])
            return {'kind':'DRIFT','mode':self.mode,'status':result,'reason':'NATIVE_REFRESH_ONLY' if result!='UNKNOWN' else 'OBSERVATION_UNAVAILABLE_OR_STALE','changes':rows,'alerts':alerts}
    def status(self):
        rows=[]
        with self.store.transaction() as (db,s):
            native=s.get('native',{});managed={tuple(x) for x in native.get('managed',[])}
            jobs=[self.public_job(json.loads(p),status,s) for p,status in db.execute('SELECT payload,status FROM jobs ORDER BY rowid DESC LIMIT 30')]
            events=[{k:r[k] for k in ('kind','job','serial','recorded_at')}|{'sequence':r['seq']} for (p,) in db.execute('SELECT payload FROM audit ORDER BY seq DESC LIMIT 30') for r in [json.loads(p)]]
            serial=s['serial'];busy=s['active_job'] is not None;complete=s['complete']
        if self.mode=='LIVE_VERIFIED' and (not complete or busy):
            rows=[{'id':'observation-unavailable','resource_type':'unsupported','status':'UNKNOWN','owned':False}]
        elif self.mode=='LIVE_VERIFIED':
            try:
                rows=[{'id':str(uuid.uuid5(uuid.NAMESPACE_OID,r['type']+r['id'])),'resource_type':r['type'],'status':'OBSERVED_LIVE','owned':r['owned']} for r in self.aws.inventory(managed)]
            except Exception:rows=[{'id':'observation-unavailable','resource_type':'unsupported','status':'UNKNOWN','owned':False}]
        return {'kind':'STATUS','mode':self.mode,'inventory':rows,'history':jobs,'audit':events,'state_serial':serial,'busy':busy,'budget_limit_usd':self.c['budget_usd']}
    def reconcile(self):
        with self.store.transaction() as (db,s):require(s['desired'] is not None,'DECLARED_CONFIGURATION_REQUIRED');c=deepcopy(s['desired'])
        return self.preview(c,'RECONCILE')
    def delete_preview(self):
        with self.store.transaction() as (db,s):require(s['desired'] is not None,'DECLARED_CONFIGURATION_REQUIRED');c=deepcopy(s['desired'])
        for n in ('vpc','ec2','s3'):c[n]['enabled']=False
        return self.preview(c,'DELETE')
    def recover(self,jid):
        with self.store.transaction() as (db,s):
            j,status,_=self.store.job(db,jid);require(status=='RECOVERY_REQUIRED' and s['active_job'] is None,'MANUAL_INTERRUPTED_PROCESS_INSPECTION_REQUIRED')
            require(self.ready()!=j['approval'],'FRESH_OWNER_RECOVERY_AUTHORIZATION_REQUIRED')
        return self.preview(j['config'],'RECOVERY')
    def simulate(self,scenario):raise ValueError('MOCK_SCENARIOS_FORBIDDEN_IN_LIVE_MODE')
