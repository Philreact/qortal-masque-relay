import time
import unittest
import json
from types import SimpleNamespace
import RNS
from masque_discovery_codec import encode, decode, MAX_PAYLOAD


class DiscoveryCodecTests(unittest.TestCase):
    def setUp(self):
        self.identity = RNS.Identity()

    def packet(self, groups=None, **overrides):
        values = dict(host="8.8.8.8", port=47322, name="qortal-masque-relay",
                      pin="ab" * 32, expiry=int(time.time()) + 600,
                      mode="groups" if groups else "public", groups=groups or [])
        values.update(overrides)
        return encode(self.identity, **values)

    def test_public_and_sixteen_maximum_groups_fit_reticulum_announce(self):
        for host in ("8.8.8.8", "2606:4700:4700::1111"):
            for groups in ([], list(range(2**31 - 16, 2**31))):
                packet = self.packet(groups, host=host)
                self.assertLessEqual(len(packet), MAX_PAYLOAD)
                decoded = decode(packet)
                self.assertEqual(decoded["allowedGroupIds"], groups)
                self.assertEqual(decoded["h"], host)
                self.assertEqual(decoded["relayIdentity"], self.identity.get_public_key()[32:].hex())

    def test_tampered_payload_or_signature_is_rejected(self):
        packet = self.packet([1144])
        for offset in (5, 20, len(packet) - 1):
            tampered = bytearray(packet)
            tampered[offset] ^= 1
            with self.assertRaises(Exception):
                decode(bytes(tampered))

    def test_expired_and_over_budget_payloads_rejected(self):
        with self.assertRaises(ValueError):
            decode(self.packet(expiry=int(time.time()) - 1))
        with self.assertRaises(ValueError):
            self.packet(list(range(2**31 - 16, 2**31)), host="2606:4700:4700::1111", name="x" * 128)

    def test_invalid_restrictions_never_become_public(self):
        for groups in ([1, 1], [0], [-1], [2**31], list(range(1, 18))):
            with self.assertRaises(ValueError):
                self.packet(groups)
        with self.assertRaises(ValueError):
            self.packet(mode="groups")

    def test_only_public_mode_advertises_legacy_compatibility(self):
        from masque_relay_discovery import RelayDiscovery
        args = SimpleNamespace(host="8.8.8.8", port=47322, server_name="relay.test",
            cert_sha256="ab" * 32, access_mode="public", allowed_group_ids="[]")
        relay = RelayDiscovery(args)
        relay.signing_identity = self.identity
        public = relay.advertisement_payloads()
        self.assertEqual(len(public), 2)
        self.assertEqual(decode(public[0])["accessMode"], "public")
        self.assertEqual(json.loads(public[1])["v"], 1)
        args.access_mode = "groups"
        args.allowed_group_ids = "[1144]"
        relay.ticket_request = lambda *_: {"keyId":"cd"*32}
        restricted = relay.advertisement_payloads()
        self.assertEqual(len(restricted), 1)
        self.assertEqual(decode(restricted[0])["allowedGroupIds"], [1144])
        self.assertEqual(decode(restricted[0])["v"], 3)

    def test_v3_max_groups_ipv6_and_key_commitment(self):
        packet = self.packet(list(range(2**31-16, 2**31)), host="2606:4700:4700::1111", ticket_key="cd"*32)
        self.assertEqual(len(packet), 316)
        value = decode(packet)
        self.assertEqual(value["ticketIdentity"], self.identity.get_public_key().hex())
        self.assertEqual(value["ticketKeyId"], "cd"*32)
        for offset in (-160, -100, -80):
            bad = bytearray(packet); bad[offset] ^= 1
            with self.assertRaises(Exception): decode(bytes(bad))


if __name__ == "__main__":
    unittest.main()
