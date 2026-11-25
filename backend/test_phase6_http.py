"""Loopback mock API integration with deterministic gate test doubles."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cloudguard.phase6.engine import Engine
from cloudguard.phase6.http import Service,handler
from cloudguard.phase6.gates import MANDATORY
ROOT=Path(__file__).resolve().parents[1]
class Fixtures:
    def run(self,folder):return {k:{'status':'PASS','reason':'MOCK_TEST_EVIDENCE'} for k in MANDATORY if k!='cost'}
class Phase6HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.engine=Engine(Path(self.tmp.name),runner=Fixtures(),clock=lambda:1795680000,source=lambda:'fixture')
        self.service=Service(self.engine,'mock-operator-secret-at-least-32-characters')
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.service));self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.stop)
    def stop(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def post(self,action,body,headers=None):
        h={'Host':'127.0.0.1:8790','Origin':'http://127.0.0.1:5173','Content-Type':'application/json','X-CloudGuard-Client':'phase6-mock'};h.update(headers or {})
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10);c.request('POST','/api/phase6/'+action,json.dumps(body),h);r=c.getresponse();out=(r.status,json.loads(r.read()),dict(r.getheaders()));c.close();return out
    def login(self):
        status,value,h=self.post('login',{'token':'mock-operator-secret-at-least-32-characters'});self.assertEqual(status,200)
        self.assertIn('HttpOnly',h['Set-Cookie']);self.assertIn('SameSite=Strict',h['Set-Cookie'])
        return {'Cookie':h['Set-Cookie'].split(';')[0],'X-CSRF-Token':value['data']['csrf']}
    def test_authenticated_operator_preview_and_mock_deploy_without_review(self):
        h=self.login();c=json.loads((ROOT/'tests/fixtures/phase6/configuration.json').read_text())
        status,r,_=self.post('preview',{'configuration':c},h);self.assertEqual(status,200);self.assertTrue(r['data']['can_deploy'])
        import uuid
        status,r,_=self.post('deploy',{'plan_id':r['data']['id'],'confirmation':'','request_id':str(uuid.uuid4())},h)
        self.assertEqual(status,200);self.assertEqual(r['data']['status'],'MOCK_SUCCEEDED')
        self.assertTrue(self.post('status',{},h)[1]['data']['inventory'])
    def test_missing_auth_csrf_bad_origin_host_and_reviewer_endpoint_deny(self):
        self.assertEqual(self.post('status',{})[0],400);h=self.login()
        for override in [{'X-CSRF-Token':''},{'Origin':'https://untrusted.invalid'},{'Host':'untrusted.invalid'},{'X-CloudGuard-Client':''}]:
            self.assertEqual(self.post('status',{},dict(h,**override))[0],400)
        self.assertEqual(self.post('approve',{},h)[0],400)
        self.assertEqual(self.post('preview',{'configuration':{},'gates':'PASS'},h)[0],400)
    def test_invalid_output_and_private_exception_never_echoed(self):
        h=self.login()
        with patch.object(self.engine,'status',return_value={'PRIVATE_CANARY':'PRIVATE_CANARY'}):
            status,r,_=self.post('status',{},h);self.assertEqual(status,400);self.assertNotIn('PRIVATE_CANARY',json.dumps(r))
        with patch.object(self.engine,'status',side_effect=ValueError('PRIVATE_CANARY')):
            self.assertNotIn('PRIVATE_CANARY',json.dumps(self.post('status',{},h)[1]))
    def test_logout_revokes_session(self):
        h=self.login();self.assertEqual(self.post('logout',{},h)[0],200);self.assertEqual(self.post('status',{},h)[0],400)
if __name__=='__main__':unittest.main()
