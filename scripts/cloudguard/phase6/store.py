"""Private SQLite mock state, serial locking, sealed jobs and chained audit events."""
from contextlib import contextmanager,closing
import json
import os
from pathlib import Path
import sqlite3
import uuid
import time
from .config import canonical,digest,require

class Store:
    def __init__(self,folder,clock=time.time):
        self.clock=clock
        self.folder=Path(folder).resolve();self.folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path=self.folder/'mock-state.sqlite'
        fresh=not self.path.exists()
        if fresh:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            with closing(sqlite3.connect(self.path)) as db:
                db.executescript('CREATE TABLE state (id INTEGER PRIMARY KEY,payload TEXT,seal TEXT); CREATE TABLE jobs (id TEXT PRIMARY KEY,payload TEXT,seal TEXT,status TEXT,request_id TEXT UNIQUE); CREATE TABLE audit (seq INTEGER PRIMARY KEY,payload TEXT,seal TEXT);')
                state={'lineage':str(uuid.uuid4()),'serial':0,'desired':None,'declared':{},'observed':{},'observed_revision':0,'complete':True,'active_job':None,'alerts':[],'inventory_ids':{}}
                self.save(db,state,'INITIALIZED');db.commit()
    def verify(self,db):
        row=db.execute('SELECT payload,seal FROM state WHERE id=1').fetchone();require(row is not None,'STATE_UNAVAILABLE')
        state=json.loads(row[0]);require(digest(state)==row[1],'STATE_INTEGRITY')
        prev='0'*64;seq=0;job_seals={}
        for raw,seal in db.execute('SELECT payload,seal FROM audit ORDER BY seq'):
            item=json.loads(raw);seq+=1
            require(item['seq']==seq and item['previous']==prev and digest(item)==seal,'AUDIT_INTEGRITY')
            if item['kind']=='PLAN_PREVIEW':job_seals[item['job']]=item['job_seal']
            prev=seal
        require(seq>0 and item['state_seal']==row[1],'AUDIT_INTEGRITY')
        for jid,payload,seal in db.execute('SELECT id,payload,seal FROM jobs'):
            require(digest(json.loads(payload))==seal and job_seals.get(jid)==seal,'PLAN_INTEGRITY')
        return state
    @contextmanager
    def transaction(self):
        require(self.path.is_file() and not self.path.is_symlink(),'STATE_UNAVAILABLE')
        with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            state=self.verify(db)
            try:yield db,state;db.commit()
            except Exception:db.rollback();raise
    def save(self,db,state,kind,job=None,job_seal=None):
        seal=digest(state)
        db.execute('INSERT OR REPLACE INTO state VALUES (1,?,?)',(canonical(state),seal))
        last=db.execute('SELECT seq,seal FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        seq=last[0]+1 if last else 1;require(seq<=10000,'AUDIT_CAPACITY')
        event={'recorded_at':self.clock(),'seq':seq,'previous':last[1] if last else '0'*64,'actor':'operator','kind':kind,'job':job,'job_seal':job_seal,'state_seal':seal,'serial':state['serial']}
        db.execute('INSERT INTO audit VALUES (?,?,?)',(seq,canonical(event),digest(event)))
    def job(self,db,jid):
        row=db.execute('SELECT payload,status,request_id FROM jobs WHERE id=?',(jid,)).fetchone();require(row is not None,'PLAN_NOT_FOUND')
        return json.loads(row[0]),row[1],row[2]
