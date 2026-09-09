#!/usr/bin/env python3


import argparse
import ipaddress
import http.client
import socket
import json
import os
import secrets
import signal
import threading
import time

import RNS
from masque_discovery_codec import encode

APP_NAMESPACE = "qortal-hub-v3"
ASPECT = "community-masque-relay"
VERSION = "v1"
ANNOUNCE_INTERVAL_SECONDS = 120
LEASE_SECONDS = 600
QUERY_RESPONSE_MIN_INTERVAL_SECONDS = 1
QUERY_RESPONSE_JITTER_MILLISECONDS = 250


def parse_args():
    parser = argparse.ArgumentParser(
        description="Broadcast a Qortal MASQUE relay through Reticulum"
    )
    parser.add_argument("--rns-config", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--allow-local", action="store_true")
    parser.add_argument("--access-mode", choices=["public", "groups"], default="public")
    parser.add_argument("--allowed-group-ids", default="[]")
    parser.add_argument("--ticket-socket")
    return parser.parse_args()


class RelayDiscovery:
    def __init__(self, args):
        self.args = args
        self.stopped = threading.Event()
        self.destination = None
        self.local_hash = None
        self.last_query_response_at = 0.0
        self.response_lock = threading.Lock()
        self.ticket_slots = threading.BoundedSemaphore(8)
        self.ticket_links = set()
        self.ticket_link_lock = threading.Lock()

    def ticket_link_established(self, link):
        with self.ticket_link_lock:
            if len(self.ticket_links) >= 64:
                link.teardown()
                return
            self.ticket_links.add(link)
        def close(_=None):
            with self.ticket_link_lock: self.ticket_links.discard(link)
            timer.cancel()
        timer = threading.Timer(30, link.teardown)
        timer.daemon = True
        link.set_link_closed_callback(close)
        timer.start()

    def ticket_request(self, path, data):
        class UnixHTTP(http.client.HTTPConnection):
            def connect(conn):
                conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.sock.settimeout(8)
                conn.sock.connect(self.args.ticket_socket)
        conn = UnixHTTP("localhost", timeout=8)
        try:
            conn.request("POST", path, body=json.dumps(data, separators=(",", ":")), headers={"Content-Type":"application/json"})
            resp = conn.getresponse()
            raw = resp.read(8193)
            if len(raw) > 8192: raise ValueError("oversized authority response")
            if resp.status != 200:
                return {"error": resp.getheader("Qortal-Relay-Error") or "RELAY_AUTH_UNAVAILABLE"}
            return json.loads(raw)
        finally:
            conn.close()

    def ticket_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not self.ticket_slots.acquire(blocking=False):
            return {"error":"RELAY_AUTH_RATE_LIMITED"}
        try:
            if not isinstance(data, bytes) or len(data) > 8192:
                return {"error":"RELAY_PROOF_INVALID"}
            value = json.loads(data)
            if not isinstance(value, dict): return {"error":"RELAY_PROOF_INVALID"}
            return self.ticket_request(path, value)
        except Exception:
            return {"error":"RELAY_AUTH_UNAVAILABLE"}
        finally:
            self.ticket_slots.release()

    def validate(self):
        address = ipaddress.ip_address(self.args.host)
        if not address.is_global and not (
            self.args.allow_local and address.is_loopback
        ):
            raise ValueError("advertised host must be a global literal IP")
        if self.args.port < 1 or self.args.port > 65535:
            raise ValueError("advertised port is invalid")
        if not self.args.server_name or len(self.args.server_name) > 128:
            raise ValueError("server name is invalid")
        if any(
            ch
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
            for ch in self.args.server_name
        ):
            raise ValueError("server name contains unsupported characters")
        pin = self.args.cert_sha256.strip().lower()
        if len(pin) != 64 or any(ch not in "0123456789abcdef" for ch in pin):
            raise ValueError("certificate pin must be a SHA-256 hex digest")
        self.args.cert_sha256 = pin

    def start(self):
        self.validate()
        os.makedirs(self.args.rns_config, exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.args.identity)), exist_ok=True)
        RNS.Reticulum(configdir=self.args.rns_config)
        identity = None
        if os.path.isfile(self.args.identity):
            try:
                identity = RNS.Identity.from_file(self.args.identity)
            except Exception:
                pass
        if identity is None:
            identity = RNS.Identity()
            identity.to_file(self.args.identity)
            try:
                os.chmod(self.args.identity, 0o600)
            except Exception:
                pass
        self.destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAMESPACE,
            ASPECT,
            VERSION,
        )
        self.local_hash = self.destination.hash
        self.signing_identity = identity
        if self.args.access_mode == "groups":
            if not self.args.ticket_socket: raise ValueError("restricted relay requires ticket authority")
            self.destination.set_max_request_size(9216)
            self.destination.set_link_established_callback(self.ticket_link_established)
            for path in ("/catalog", "/challenge", "/issue"):
                self.destination.register_request_handler(path, response_generator=self.ticket_handler, allow=RNS.Destination.ALLOW_ALL)
            # The stable service destination is announced for encrypted RNS Links.
            self.destination.announce()
        print(
            f"MASQUE relay discovery destination {self.local_hash.hex()}",
            flush=True,
        )
        RNS.Transport.register_announce_handler(self.AnnounceHandler(self))
        self.announce()
        print(
            "MASQUE relay availability announced through Reticulum",
            flush=True,
        )
        while not self.stopped.wait(ANNOUNCE_INTERVAL_SECONDS):
            self.announce()

    def announce(self):
        if self.destination is None or self.stopped.is_set():
            return
        if self.args.access_mode == "groups": self.destination.announce()
        # Advertisements are self-authenticating through their Reticulum
        # signature and carry the pinned TLS certificate for the actual relay.
        # Use a fresh anonymous destination so transport nodes do not suppress
        # a periodic advertisement as a repeated path announce.
        for payload in self.advertisement_payloads():
            advertisement_identity = RNS.Identity()
            advertisement_destination = RNS.Destination(
                advertisement_identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                APP_NAMESPACE,
                ASPECT,
                VERSION,
            )
            advertisement_destination.announce(app_data=payload)
        print("MASQUE relay availability lease refreshed", flush=True)

    def advertisement_payload(self):
        ticket_key = None
        if self.args.access_mode == "groups":
            catalog = self.ticket_request("/catalog", {})
            ticket_key = catalog["keyId"]
        return encode(self.signing_identity, self.args.host, self.args.port,
                      self.args.server_name, self.args.cert_sha256,
                      int(time.time()) + LEASE_SECONDS, self.args.access_mode,
                      json.loads(self.args.allowed_group_ids), ticket_key)

    def advertisement_payloads(self):
        # Old Hubs can continue using public relays. Never publish a legacy
        # public hint for a restricted relay. New Hubs prefer signed v2.
        payloads = [self.advertisement_payload()]
        if self.args.access_mode == "public":
            payloads.append(json.dumps({"v": 1, "h": self.args.host,
                "p": self.args.port, "s": self.args.server_name,
                "c": self.args.cert_sha256, "x": int(time.time()) + LEASE_SECONDS},
                separators=(",", ":")).encode())
        return payloads

    def answer_query(self, query_identity, query_hash):
        with self.response_lock:
            now = time.monotonic()
            if now - self.last_query_response_at < QUERY_RESPONSE_MIN_INTERVAL_SECONDS:
                return
            self.last_query_response_at = now
        print("MASQUE relay discovery query received", flush=True)
        timer = threading.Timer(
            secrets.randbelow(QUERY_RESPONSE_JITTER_MILLISECONDS) / 1000.0,
            self.send_query_response,
            args=(query_identity, query_hash),
        )
        timer.daemon = True
        timer.start()

    def send_query_response(self, query_identity, query_hash):
        try:
            response_destination = RNS.Destination(
                query_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                APP_NAMESPACE,
                ASPECT,
                VERSION,
            )
            if response_destination.hash != query_hash:
                return
            for payload in self.advertisement_payloads():
                packet = RNS.Packet(response_destination, payload, create_receipt=False)
                packet.send()
            print("MASQUE relay discovery response sent", flush=True)
        except Exception as exc:
            print(f"MASQUE relay discovery response failed: {exc}", flush=True)

    def stop(self, *_args):
        self.stopped.set()

    class AnnounceHandler:
        def __init__(self, owner):
            self.owner = owner
            self.aspect_filter = f"{APP_NAMESPACE}.{ASPECT}.{VERSION}"

        def received_announce(self, destination_hash, announced_identity, app_data):
            if destination_hash == self.owner.local_hash:
                return
            try:
                raw = bytes(app_data or b"")
                if len(raw) > 128:
                    return
                value = json.loads(raw.decode("utf-8"))
                if (
                    isinstance(value, dict)
                    and int(value.get("v") or 0) == 1
                    and value.get("q") is True
                ):
                    print(
                        "MASQUE relay discovery query source "
                        + destination_hash.hex(),
                        flush=True,
                    )
                    self.owner.answer_query(announced_identity, destination_hash)
            except Exception:
                return


def main():
    relay = RelayDiscovery(parse_args())
    signal.signal(signal.SIGINT, relay.stop)
    signal.signal(signal.SIGTERM, relay.stop)
    relay.start()


if __name__ == "__main__":
    main()
