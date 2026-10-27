import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import RNS
from masque_discovery_codec import decode
from masque_relay_discovery import RelayDiscovery


class StopAfterWaits:
    def __init__(self, count):
        self.count = count
        self.waits = []
        self.stopped = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, delay):
        self.waits.append(delay)
        if len(self.waits) >= self.count:
            self.stopped = True
        return self.stopped


class DiscoveryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(host='8.8.8.8', port=47322,
            server_name='relay.test', cert_sha256='ab' * 32,
            access_mode='public', allowed_group_ids='[]')
        self.relay = RelayDiscovery(self.args)
        self.relay.signing_identity = RNS.Identity()
        self.relay.destination = Mock()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_temporary_catalog_failure_recovers_without_exiting(self):
        self.args.access_mode = 'groups'
        self.args.allowed_group_ids = '[42]'
        self.relay.stopped = StopAfterWaits(3)
        self.relay.ticket_request = Mock(side_effect=[
            TimeoutError('temporary socket delay'),
            {'error': 'RELAY_AUTH_UNAVAILABLE'},
            {'keyId': 'cd' * 32},
        ])
        published = []
        with patch.object(RNS.Transport, 'owner', SimpleNamespace(is_connected_to_shared_instance=False), create=True), \
             patch.object(RNS.Destination, 'announce', side_effect=lambda **kw: published.append(kw['app_data'])):
            self.relay.run_announcements()
        self.assertEqual(self.relay.stopped.waits, [5, 10, 120])
        self.assertEqual(len(published), 1)
        self.assertEqual(decode(published[0])['ticketKeyId'], 'cd' * 32)
        self.assertEqual(decode(published[0])['accessMode'], 'groups')

    def test_backoff_is_bounded_and_resets_after_success(self):
        self.relay.stopped = StopAfterWaits(9)
        self.relay.announce = Mock(side_effect=[OSError('offline')] * 6 + [None, OSError('offline'), None])
        self.relay.run_announcements()
        self.assertEqual(self.relay.stopped.waits, [5, 10, 20, 40, 60, 60, 120, 5, 120])

    def test_stop_interrupts_retry_wait(self):
        self.relay.stopped = StopAfterWaits(1)
        self.relay.announce = Mock(side_effect=OSError('offline'))
        self.relay.run_announcements()
        self.relay.announce.assert_called_once()
        self.assertTrue(self.relay.stopped.is_set())

    def test_refreshes_do_not_accumulate_registered_destinations(self):
        baseline = set(RNS.Transport.destinations)
        captured = []
        def queued(destination, **kwargs):
            # Simulate a deferred outbound packet retaining its destination.
            captured.append((destination, kwargs['app_data']))
        with patch.object(RNS.Transport, 'owner', SimpleNamespace(is_connected_to_shared_instance=False), create=True), \
             patch.object(RNS.Destination, 'announce', queued):
            for _ in range(50):
                self.relay.announce()
        self.assertEqual(set(RNS.Transport.destinations), baseline)
        self.assertEqual(len(captured), 100)
        self.assertEqual(len({d.hash for d, _ in captured}), 100)
        for destination, payload in captured:
            self.assertNotIn(destination.hash, RNS.Transport.destinations_map)
            self.assertIsNotNone(destination.identity)
            if payload[0] == 2:
                self.assertEqual(decode(payload)['accessMode'], 'public')

    def test_failed_send_also_releases_registration(self):
        baseline = set(RNS.Transport.destinations)
        with patch.object(RNS.Transport, 'owner', SimpleNamespace(is_connected_to_shared_instance=False), create=True), \
             patch.object(RNS.Destination, 'announce', side_effect=OSError('interface gone')):
            with self.assertRaises(OSError):
                self.relay.announce()
        self.assertEqual(set(RNS.Transport.destinations), baseline)


if __name__ == '__main__':
    unittest.main()
