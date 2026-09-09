"""Integration helper: exercise the actual Hub bridge handler on isolated RNS."""
import importlib.util
import json
import os
import sys
import threading
import RNS

spec = importlib.util.spec_from_file_location("hub_test_bridge", sys.argv[1])
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
RNS.Reticulum(configdir=sys.argv[2], loglevel=RNS.LOG_CRITICAL)
for line in sys.stdin:
    done = threading.Event()
    def response(req_id, ok, payload=None, error=None):
        print(json.dumps({"ok": ok, "payload": payload, "error": error}), flush=True)
        done.set()
    bridge.emit_resp = response
    bridge.handle_relay_ticket_request("test", json.loads(line))
    if not done.wait(28):
        print(json.dumps({"ok":False,"error":"test timeout"}), flush=True)
os._exit(0)
