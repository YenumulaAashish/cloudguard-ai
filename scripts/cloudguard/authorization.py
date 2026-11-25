"""Trusted-runner quota authority. No cloud calls, credentials or implicit initialization."""
from contextlib import contextmanager, closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid

REPOSITORY = 'YenumulaAashish/cloudguard-ai'
SUBJECT = 'repo:YenumulaAashish@212769106/cloudguard-ai@1379194368:environment:aws-plan'
WORKFLOW = REPOSITORY + '/.github/workflows/terraform-plan.yml@refs/heads/main'


def require(value):
    if not value:
        raise ValueError('PLANNING_AUTHORIZATION_DENIED')


def timestamp(value):
    require(type(value) is str and value.endswith('Z'))
    result = datetime.fromisoformat(value[:-1] + '+00:00')
    require(result.utcoffset().total_seconds() == 0)
    return result.timestamp()


def digest(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_grant(g):
    require(type(g) is dict and set(g) == {'version','id','approval','owner','approved_at','starts_at','expires_at','max_attempts','max_daily','allow_self_review','scope'})
    require(type(g['version']) is int and g['version'] == 1 and g['approval'] == 'APPROVED' and g['owner'] == 'YenumulaAashish')
    require(re.fullmatch(r'CG-PLAN-[A-Z0-9-]{1,48}', g['id']))
    start, end = timestamp(g['starts_at']), timestamp(g['expires_at'])
    require(timestamp(g['approved_at']) <= start < end and end-start <= 7*86400)
    require(type(g['max_attempts']) is int and 1 <= g['max_attempts'] <= 5)
    require(type(g['max_daily']) is int and 1 <= g['max_daily'] <= 2)
    require(type(g['allow_self_review']) is bool)
    s=g['scope']
    require(type(s) is dict and set(s) == {'repository','repository_id','owner_id','ref','workflow','subject','audience','region','role','bucket','sha','source_digest'})
    require((s['repository'],s['repository_id'],s['owner_id'],s['ref'],s['workflow'],s['subject'],s['audience'],s['region']) ==
            (REPOSITORY,'1379194368','212769106','refs/heads/main',WORKFLOW,SUBJECT,'sts.amazonaws.com','ap-south-1'))
    require(re.fullmatch(r'arn:aws:iam::[0-9]{12}:role/cloudguard-ai-plan',s['role']))
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]',s['bucket']))
    require(re.fullmatch(r'[0-9a-f]{40}',s['sha']) and re.fullmatch(r'[0-9a-f]{64}',s['source_digest']))
    return g


def context(env):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1' and env.get('RUNNER_ENVIRONMENT') == 'self-hosted')
    require(env.get('RUNNER_OS') == 'Linux' and re.fullmatch(r'[1-9][0-9]{0,19}',env.get('GITHUB_RUN_ID','')))
    return {'repository':env.get('GITHUB_REPOSITORY'),'repository_id':env.get('GITHUB_REPOSITORY_ID'),
            'owner_id':env.get('GITHUB_REPOSITORY_OWNER_ID'),'ref':env.get('GITHUB_REF'),
            'workflow':env.get('GITHUB_WORKFLOW_REF'),'subject':SUBJECT,'audience':'sts.amazonaws.com',
            'region':env.get('AWS_REGION'),'role':env.get('PLAN_ROLE'),'bucket':env.get('TF_VAR_bucket_name'),
            'sha':env.get('GITHUB_SHA'),'source_digest':env.get('CLOUDGUARD_SOURCE_DIGEST')}


class Ledger:
    """Local trusted disk only. Stale locks, partial commits and damaged anchors deny.

    The sidecar detects a DB-only rollback. A privileged operator restoring BOTH
    files or malicious trusted code can defeat quotas; recovery needs reapproval.
    This is not an IAM-enforced quota or a sandbox against an administrator.
    """
    def __init__(self, path):
        self.path = Path(path)
        self.anchor = Path(str(path)+'.anchor')
        self.lock = Path(str(path)+'.lock')

    @contextmanager
    def exclusive(self):
        require(self.path.parent.is_dir())
        fd=os.open(self.lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            os.close(fd)
            yield
        finally:
            self.lock.unlink()

    def initialize(self, grant):
        validate_grant(grant)
        with self.exclusive():
            require(not self.path.exists() and not self.anchor.exists())
            # Never called by a workflow. Separate explicit owner approval required.
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            state={'grant':grant,'attempts':[],'revoked':False,'last_time':timestamp(grant['approved_at'])}
            with closing(sqlite3.connect(self.path)) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)')
                db.execute('INSERT INTO ledger VALUES (1,?)',(json.dumps(state),));db.commit()
            with self.anchor.open('x',encoding='ascii') as f:
                f.write(digest(state));f.flush();os.fsync(f.fileno())

    def transact(self, action):
        with self.exclusive():
            require(self.path.is_file() and self.anchor.is_file() and not self.path.is_symlink() and not self.anchor.is_symlink())
            with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=1)) as db:
                db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
                rows=db.execute('SELECT payload FROM ledger WHERE id=1').fetchall()
                require(len(rows)==1 and len(rows[0][0])<=65536)
                state=json.loads(rows[0][0]);require(self.anchor.read_text()==digest(state))
                validate_grant(state['grant'])
                result=action(state)
                db.execute('UPDATE ledger SET payload=? WHERE id=1',(json.dumps(state),));db.commit()
            # Crash before sidecar replacement leaves a mismatch and blocks future use.
            tmp=Path(str(self.anchor)+'.tmp')
            with tmp.open('x',encoding='ascii') as f:
                f.write(digest(state));f.flush();os.fsync(f.fileno())
            os.replace(tmp,self.anchor)
            return result

    def approved_grant(self):
        # Verified sidecar/DB read under the same exclusive transaction protocol.
        return self.transact(lambda s:json.loads(json.dumps(s['grant'])))

    def reserve(self, run_id, scope, now):
        def change(s):
            g=s['grant'];require(not s['revoked'] and scope==g['scope'])
            require(re.fullmatch(r'[1-9][0-9]{0,19}',run_id))
            require(s['last_time'] <= now and timestamp(g['starts_at']) <= now < timestamp(g['expires_at']))
            attempts=s['attempts'];require(not any(a['run_id']==run_id for a in attempts))
            require(all(a['status'] in ('COMPLETE','FAILED','CANCELLED') for a in attempts))
            # Whole-job timeout is 25 minutes; reserve a 40-minute margin to
            # prevent midnight spillover and leave room for the 15-minute STS session.
            utc=datetime.fromtimestamp(now,timezone.utc)
            next_day=(utc.replace(hour=0,minute=0,second=0,microsecond=0).timestamp()+86400)
            require(now+2400<=min(next_day,timestamp(g['expires_at'])))
            day=utc.date().isoformat()
            require(len(attempts)<g['max_attempts'] and sum(a['day']==day for a in attempts)<g['max_daily'])
            nonce=str(uuid.uuid4());attempts.append({'run_id':run_id,'nonce':nonce,'day':day,'status':'RESERVED','reserved_at':now})
            s['last_time']=now
            return nonce
        return self.transact(change)

    def transition(self, run_id, nonce, status, now, scope=None):
        def change(s):
            a=next((a for a in s['attempts'] if a['run_id']==run_id and a['nonce']==nonce),None)
            require(a is not None and s['last_time'] <= now)
            if status=='STARTED':
                require(not s['revoked'] and scope==s['grant']['scope'] and a['status']=='RESERVED')
                require(timestamp(s['grant']['starts_at'])<=now<timestamp(s['grant']['expires_at']))
            else:
                require(status in ('COMPLETE','FAILED','CANCELLED') and a['status'] in ('RESERVED','STARTED'))
            a['status']=status;s['last_time']=now
            a['started_at' if status=='STARTED' else 'finished_at']=now
            return timestamp(s['grant']['expires_at'])
        return self.transact(change)

    def revoke(self):
        self.transact(lambda s:s.update(revoked=True))
