"""Cross-project integration: real relay + real Hub sidecar, generated keys.

Run with RELAY_TEST_BINARY and HUB_SIDECAR_TEST_BINARY pointing to Go builds,
and HUB_BRIDGE_TEST_PATH pointing to Hub's presence_bridge.py.
No production service, account, Core, or discovery state is modified.
"""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import threading
import time
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b58(raw):
    value = int.from_bytes(raw, "big")
    result = ""
    while value:
        value, digit = divmod(value, 58)
        result = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[digit] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def address(key):
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = bytes([58]) + hashlib.new("ripemd160", hashlib.sha256(public).digest()).digest()
    return b58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


def proof(challenge, key):
    fields = dict(challenge, authorAddress=address(key),
                  authorPublicKey=b58(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
    fields["signature"] = b58(key.sign(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()))
    return json.dumps(fields, separators=(",", ":"))


def read_json(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(30):
            raise TimeoutError("test process did not respond")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("test process exited unexpectedly")
    return json.loads(line)


@unittest.skipUnless(
    os.environ.get("RELAY_TEST_BINARY")
    and os.environ.get("HUB_SIDECAR_TEST_BINARY")
    and os.environ.get("HUB_BRIDGE_TEST_PATH"),
    "set RELAY_TEST_BINARY, HUB_SIDECAR_TEST_BINARY, and HUB_BRIDGE_TEST_PATH",
)
class HubSidecarAccessTest(unittest.TestCase):
    def test_membership_proof_forwarding_replay_and_clear(self):
        member = Ed25519PrivateKey.generate()
        member_address = address(member)
        class Core(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                addresses = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps([{"address":addresses[0],"isMember":addresses[0] == member_address}]).encode())
        core = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Core)
        threading.Thread(target=core.serve_forever, daemon=True).start()
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 0))
        def echo_loop():
            while True:
                try:
                    data, source = echo.recvfrom(1500)
                    echo.sendto(data, source)
                except OSError:
                    return
        threading.Thread(target=echo_loop, daemon=True).start()
        reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reservation.bind(("127.0.0.1", 0))
        endpoint = f"127.0.0.1:{reservation.getsockname()[1]}"
        reservation.close()
        relay = sidecar = rns_client = None
        with tempfile.TemporaryDirectory(prefix="hub-relay-access-test-") as directory:
            try:
                config = Path(directory) / "access.json"
                config.write_text(json.dumps({"mode":"groups","allowed_group_ids":[1144],
                    "core_url_bases":[f"http://127.0.0.1:{core.server_port}"]}))
                target = f"127.0.0.1:{echo.getsockname()[1]}"
                tcp = socket.socket(); tcp.bind(("127.0.0.1",0)); rns_port=tcp.getsockname()[1];tcp.close()
                relay_rns=Path(directory)/"rns-relay";relay_rns.mkdir()
                client_rns=Path(directory)/"rns-client";client_rns.mkdir()
                relay_rns.joinpath("config").write_text(f"[reticulum]\n  share_instance = No\n  enable_transport = Yes\n[interfaces]\n  [[Test Server]]\n    type = TCPServerInterface\n    enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {rns_port}\n")
                client_rns.joinpath("config").write_text(f"[reticulum]\n  share_instance = No\n[interfaces]\n  [[Test Client]]\n    type = TCPClientInterface\n    enabled = Yes\n    target_host = 127.0.0.1\n    target_port = {rns_port}\n")
                relay_args=[os.environ["RELAY_TEST_BINARY"], "--listen", endpoint,
                    "--public-address", endpoint, "--upnp=false", "--state-dir", directory,
                    "--allow-local-advertise", "--rns-config",str(relay_rns),"--discovery-script",str(Path(__file__).with_name("masque_relay_discovery.py")), "--access-config", str(config),
                    "--allow-target", target]
                relay = subprocess.Popen(relay_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                metadata = read_json(relay)
                import RNS
                deadline=time.monotonic()+10
                while not Path(directory,"discovery.identity").exists() and time.monotonic()<deadline: time.sleep(.05)
                identity=RNS.Identity.from_file(str(Path(directory,"discovery.identity"))).get_public_key().hex()
                hub_bridge=os.environ["HUB_BRIDGE_TEST_PATH"]
                rns_client=subprocess.Popen([sys.executable,str(Path(__file__).with_name("rns_ticket_test_client.py")),hub_bridge,str(client_rns)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                def reticulum(path,data,error=None):
                    rns_client.stdin.write((json.dumps({"identity":identity,"path":path,"data":data})+"\n").encode());rns_client.stdin.flush()
                    result=read_json(rns_client)
                    self.assertTrue(result["ok"],result)
                    value=result["payload"]
                    if error:self.assertEqual(value.get("error"),error)
                    else:self.assertNotIn("error",value)
                    return value
                sidecar = subprocess.Popen([os.environ["HUB_SIDECAR_TEST_BINARY"]], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                counter = 0
                def request(operation, params=None, error=None):
                    nonlocal counter
                    counter += 1
                    sidecar.stdin.write((json.dumps({"version":2,"requestId":str(counter),
                        "operation":operation,"params":params or {}}) + "\n").encode())
                    sidecar.stdin.flush()
                    result = read_json(sidecar)
                    if error:
                        self.assertFalse(result["ok"], result)
                        self.assertEqual(result["error"]["code"], error)
                        return result
                    self.assertTrue(result["ok"], result)
                    return result.get("result")
                request("health")
                request("openMasqueTunnel", dict(metadata,targetAddress=target), "MASQUE_OPEN_FAILED")
                catalog=reticulum("/catalog",{})
                state=request("prepareRelayTickets",{"descriptor":catalog})
                data={"descriptor":catalog,"blinded":state["blinded"]}
                challenge=reticulum("/challenge",data)
                issued=reticulum("/issue",dict(data,proof=json.loads(proof(challenge,member))))
                finalized=request("finalizeRelayTickets",{"handle":state["handle"],"signatures":issued["signatures"]})
                self.assertEqual(len(finalized["tickets"]),3)
                first = request("prepareRelay", metadata)
                self.assertFalse(first["ready"])
                self.assertEqual(first["challenge"],{"type":"masque-ticket-required-v1"})
                signed = finalized["tickets"][0]
                authorized = request("authorizeRelay", {"handle":first["handle"],"proof":signed})
                self.assertTrue(authorized["ready"])
                self.assertGreater(authorized["expiresAt"], 0)
                tunnel = request("openMasqueTunnel", dict(metadata,targetAddress=target,preparedRelay=first["handle"]))
                echo_data = base64.b64encode(b"restricted-relay-end-to-end").decode()
                request("sendDatagram", dict(tunnel,dataBase64=echo_data))
                self.assertEqual(request("receiveDatagram", dict(tunnel,timeoutMs=2000))["dataBase64"], echo_data)
                # Renew in-place while an existing CONNECT-UDP tunnel is live.
                self.assertTrue(request("authorizeRelay", {"handle":first["handle"],"proof":finalized["tickets"][1],"renew":True})["ready"])
                request("sendDatagram", dict(tunnel,dataBase64=echo_data))
                self.assertEqual(request("receiveDatagram", dict(tunnel,timeoutMs=2000))["dataBase64"], echo_data)
                request("closeTunnel", tunnel)
                # A closed CONNECT stream must not close the shared connection.
                self.assertTrue(request("authorizeRelay", {"handle":first["handle"]})["ready"])
                request("authorizeRelay", {"handle":first["handle"],"proof":signed,"renew":True}, "RELAY_PROOF_INVALID")
                second = request("prepareRelay", metadata)
                request("authorizeRelay", {"handle":second["handle"],"proof":signed}, "RELAY_PROOF_INVALID")
                outsider = Ed25519PrivateKey.generate()
                challenge=reticulum("/challenge",data)
                reticulum("/issue",dict(data,proof=json.loads(proof(challenge,outsider))),"RELAY_ACCESS_DENIED")
                request("authorizeRelay", {"handle":second["handle"],"proof":finalized["tickets"][1]}, "RELAY_PROOF_INVALID")
                request("clearRelays")
                request("authorizeRelay", {"handle":first["handle"]}, "RELAY_CONNECTION_CLOSED")
                # Restart exactly the temporary test relay. Unused credentials
                # survive, but durable spent markers must still reject replay.
                relay.terminate();relay.wait(timeout=5);relay.stdout.close()
                relay=subprocess.Popen(relay_args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                self.assertEqual(read_json(relay),metadata)
                third=request("prepareRelay",metadata)
                request("authorizeRelay",{"handle":third["handle"],"proof":signed},"RELAY_PROOF_INVALID")
                request("authorizeRelay",{"handle":third["handle"],"proof":finalized["tickets"][2]})
            finally:
                for process in (rns_client, sidecar, relay):
                    if process:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
                        for stream in (process.stdin, process.stdout, process.stderr):
                            if stream: stream.close()
                core.shutdown();core.server_close();echo.close()


if __name__ == "__main__":
    unittest.main()
