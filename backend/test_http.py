"""Actual loopback HTTP integration, with a mocked provider and synthetic key."""
import http.client
import json
import sys
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cloudguard.live_advisory import Service, handler, FIELDS


class HttpTests(unittest.TestCase):
    def test_http_contract_and_origin(self):
        service = Service(provider=lambda *args: {k: 'Human review recommended.' for k in FIELDS}, key='synthetic-test-key')
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler(service))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def post(path, body, origin='http://127.0.0.1:5173'):
                client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                client.request('POST', path, json.dumps(body), {'Host':'127.0.0.1:8787','Origin':origin,'Content-Type':'application/json'})
                response = client.getresponse(); result = response.status, json.loads(response.read()); client.close(); return result
            status, data = post('/api/ai/catalog', {})
            self.assertEqual(status, 200); self.assertTrue(data['configured'])
            status, result = post('/api/ai/advisory', {'finding_id':data['findings'][0]['id']})
            self.assertEqual(status, 200); self.assertNotIn('synthetic-test-key', json.dumps(result))
            self.assertEqual(post('/api/ai/catalog', {}, 'https://untrusted.invalid')[0], 400)
            self.assertEqual(post('/api/ai/advisory', {'raw_plan':'x'*300})[0], 400)
            self.assertEqual(post('/api/ai/advisory', {'finding_id':'unknown','secret':'private'})[0], 400)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
