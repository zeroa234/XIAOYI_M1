"""Local fixtures only: bounded UDP capture and HTTP cleanup; no camera traffic."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import threading
import unittest
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("m1_capture", ROOT/"scripts/capture-liveview.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CaptureTests(unittest.TestCase):
    def test_local_capture_preserves_raw_and_stops_remote_mode(self):
        commands = []
        udp_open_during_stop = []
        fixture = b'{"ISOSetting":"400"}'.ljust(2048, b'\0') + b'\xff\xd8fixture\xff\xd9'
        destination = ROOT/"output/capture-tests"/uuid.uuid4().hex

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                command = json.loads(parse_qs(urlsplit(self.path).query)["data"][0])["command"]
                commands.append(command)
                if command == 'RCStopRemoteCtl':
                    try:
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                            probe.bind(('127.0.0.1',54321))
                        udp_open_during_stop.append(False)
                    except OSError:
                        udp_open_during_stop.append(True)
                body = json.dumps({"code":200,"data":{}}).encode()
                self.send_response(200)
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                if command == "RCStartRemoteCtl":
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                        # Complete ordered frame, then a two-part frame received backwards.
                        for payload in [struct.pack('>III',1,1,0)+fixture,
                            struct.pack('>III',2,2,1)+fixture[1200:],
                            struct.pack('>III',2,2,0)+fixture[:1200]]:
                            sender.sendto(payload,('127.0.0.1',54321))

        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            result = module.capture(destination,seconds=1,
                base=f'http://127.0.0.1:{server.server_port}',source='127.0.0.1',bind_address='127.0.0.1')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        self.assertNotIn('error',result)
        self.assertEqual(commands,['GetCameraStatus','RCStartRemoteCtl','RCStopRemoteCtl'])
        self.assertEqual(udp_open_during_stop,[True])
        self.assertEqual(result['orderedFramesSaved'],1)
        self.assertEqual(result['frameEvents'][0]['metadata']['ISOSetting'],'400')
        self.assertEqual(len(result['metadataEvents']),2)
        self.assertEqual({x['frameIndex'] for x in result['metadataEvents']},{1,2})
        self.assertEqual((destination/'packet_1.jpg').read_bytes(),fixture[2048:])
        self.assertFalse((destination/'packet_2.jpg').exists())
        with zipfile.ZipFile(destination/'datagrams.zip') as archive:
            manifest=json.loads(archive.read('manifest.json'))
            self.assertEqual(len(manifest['records']),3)
            self.assertEqual(archive.read('000000.udp')[12:],fixture)

    def test_rejected_session_does_not_stop_another_client(self):
        commands=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass
            def do_GET(self):
                command=json.loads(parse_qs(urlsplit(self.path).query)['data'][0])['command']
                commands.append(command)
                body=json.dumps({'code':1515 if command=='RCStartRemoteCtl' else 200}).encode()
                self.send_response(200)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            result=module.capture(ROOT/'output/capture-tests'/uuid.uuid4().hex,seconds=2,
                base=f'http://127.0.0.1:{server.server_port}',source='127.0.0.1',bind_address='127.0.0.1')
        finally:
            server.shutdown();server.server_close();worker.join(timeout=2)
        self.assertIn('error',result)
        self.assertEqual(commands,['GetCameraStatus','RCStartRemoteCtl'])

    def test_command_allowlist(self):
        with self.assertRaises(ValueError):
            module.request('UpdateFW',base='http://127.0.0.1')


if __name__=='__main__':
    unittest.main()
