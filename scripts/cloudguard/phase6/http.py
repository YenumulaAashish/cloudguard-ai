"""Loopback single-operator mock API. No reviewer accounts, AWS access or AI calls."""
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import secrets
import threading
import time
from .config import keys,require
from ..runtime import ROOT

class Service:
    def __init__(self,engine,secret,clock=time.time):
        require(type(secret) is str and 32<=len(secret)<=128,'OPERATOR_SECRET_REQUIRED')
        self.engine=engine;self.secret_hash=hashlib.sha256(secret.encode()).digest();self.clock=clock
        self.session=None;self.attempts=[];self.lock=threading.Lock()
    def login(self,body):
        keys(body,('token',));require(type(body['token']) is str and len(body['token'])<=128)
        with self.lock:
            now=self.clock();self.attempts=[n for n in self.attempts if now-n<60]
            require(len(self.attempts)<5,'LOGIN_RATE_LIMITED');self.attempts.append(now)
            require(hmac.compare_digest(hashlib.sha256(body['token'].encode()).digest(),self.secret_hash),'SESSION_REQUIRED')
            token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
            self.session={'hash':hashlib.sha256(token.encode()).digest(),'csrf':csrf,'expires':now+900}
            return {'kind':'SESSION','authenticated':True,'csrf':csrf},token
    def authorized(self,cookie,csrf=None):
        c=SimpleCookie();c.load(cookie or '');token=c['cg_phase6'].value if 'cg_phase6' in c else ''
        with self.lock:
            s=self.session
            require(s is not None and self.clock()<s['expires'] and hmac.compare_digest(hashlib.sha256(token.encode()).digest(),s['hash']),'SESSION_REQUIRED')
            if csrf is not None:require(type(csrf) is str and hmac.compare_digest(csrf,s['csrf']),'CSRF_DENIED')
            return dict(s)
    def dispatch(self,action,body,cookie,csrf):
        if action=='session':
            keys(body,())
            try:s=self.authorized(cookie);return {'kind':'SESSION','authenticated':True,'csrf':s['csrf']},None
            except ValueError:return {'kind':'SESSION','authenticated':False,'csrf':''},None
        if action=='login':return self.login(body)
        self.authorized(cookie,csrf or '')
        if action=='logout':
            keys(body,());self.session=None;return {'kind':'LOGOUT'},''
        if action in ('status','drift','reconcile','delete-preview'):
            keys(body,());fn={'status':self.engine.status,'drift':self.engine.drift,'reconcile':self.engine.reconcile,'delete-preview':self.engine.delete_preview}[action]
            return fn(),None
        if action=='preview':keys(body,('configuration',));return self.engine.preview(body['configuration']),None
        if action=='deploy':keys(body,('plan_id','confirmation','request_id'));return self.engine.execute(body['plan_id'],body['confirmation'],body['request_id']),None
        if action=='recover':keys(body,('plan_id',));return self.engine.recover(body['plan_id']),None
        if action=='simulate-drift':keys(body,('scenario',));return self.engine.simulate(body['scenario']),None
        raise ValueError('INVALID_ACTION')

def valid_response(value):
    from jsonschema import Draft202012Validator
    Draft202012Validator(json.loads((ROOT/'security/phase6-public.schema.json').read_text())).validate(value)
    return value

def handler(service):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def setup(self):super().setup();self.connection.settimeout(5)
        def do_POST(self):
            token=None
            try:
                require(self.headers.get('Host')=='127.0.0.1:8790' and self.headers.get('Origin') in ('http://127.0.0.1:5173','http://localhost:5173'),'REQUEST_DENIED')
                require(self.headers.get('X-CloudGuard-Client')=='phase6-mock' and self.headers.get('Content-Type')=='application/json' and not self.headers.get('Transfer-Encoding'),'REQUEST_DENIED')
                size=int(self.headers.get('Content-Length','0'));require(0<size<=8192,'REQUEST_DENIED')
                require(self.path.startswith('/api/phase6/') and '?' not in self.path,'REQUEST_DENIED')
                def unique(pairs):
                    value={}
                    for k,v in pairs:require(k not in value,'REQUEST_DENIED');value[k]=v
                    return value
                body=json.loads(self.rfile.read(size),object_pairs_hook=unique);require(type(body) is dict,'REQUEST_DENIED')
                data,token=service.dispatch(self.path[len('/api/phase6/'):],body,self.headers.get('Cookie'),self.headers.get('X-CSRF-Token'))
                value=valid_response({'mode':'MOCK_ONLY','ok':True,'data':data});status=200
            except Exception:
                value={'mode':'MOCK_ONLY','ok':False,'error':'REQUEST_DENIED'};status=400;token=None
            raw=json.dumps(value).encode();self.send_response(status)
            self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            if token is not None:self.send_header('Set-Cookie','cg_phase6='+token+'; HttpOnly; SameSite=Strict; Path=/api/phase6/; Max-Age='+('900' if token else '0'))
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    return Handler
