# Relay admission and discovery

`relay-access.json` is mounted read-only by Docker Compose. Choose one of the
following policies deliberately before publishing the relay. Public mode is:

```json
{
  "mode": "public",
  "allowed_group_ids": [],
  "core_url_bases": ["https://ext-node.qortal.link"]
}
```

Public mode does not query a Core or request a wallet signature. The file in
this checkout may already contain an operator-specific group policy; do not
assume that its group IDs are appropriate for your deployment. To restrict
access, set `mode` to `groups` and provide 1–16 distinct positive group IDs.
A verified member of **any one** listed group qualifies. Admin status alone
does not qualify. The array must not be empty in groups mode. Public mode
with a nonempty group array, unknown properties, malformed JSON, invalid IDs,
and invalid Core URLs all prevent startup; none silently turn restrictions off.

Core bases are an ordered list of up to eight URLs. HTTPS is required except
for a Core on localhost. Failed, malformed, or unavailable responses use the
next Core; a valid negative response is not overridden by another Core. Failed
endpoints are temporarily demoted for five seconds. If membership cannot be
established, admission fails closed. Use Core operators you trust: they are
the authority for membership and learn the queried Qortal address. Backups
improve availability, not resistance to a dishonest Core.

Apply a policy-only change with `docker compose restart relay`. Configuration
is immutable within a process, but the JSON file is bind-mounted and will be
read again when the process restarts. Restarting closes existing tunnels;
schedule policy changes accordingly. Do not add group 1144 just because it
appeared in an API example: choose the actual group(s) you intend to authorize.

## Anonymous tickets (restricted relays)

Account ownership and membership are checked **only over an encrypted Reticulum
Link**, using a one-minute, single-use challenge bound to the blinded batch.
The Python Reticulum service talks to Go over a mode-0600 Unix socket; there is
no TCP/HTTP account-authorization endpoint. Identity-bearing account proofs are
not accepted over the IP-visible QUIC connection.

Hub uses CIRCL v1.6.5's RFC 9474 RSABSSA-SHA384-PSS-Deterministic implementation.
It creates three random tickets, blinds them, obtains signatures over Reticulum,
then unblinds and verifies locally. The relay cannot directly match the redeemed
message/signature to its blinded issuance transcript. No Qortal address, account
public key, or wallet signature appears in QUIC ticket redemption.

Tickets are scoped to this relay TLS pin and group-policy hash. A shared RSA-2048
key is created for each UTC issuance hour. Expiry is that hour's start plus
12 hours: actual lifetime is 11–12 hours, never another 12 hours upon redemption.
The key commitment is included in the signed public advertisement; Hub checks it
before signing an issuance request. Per-user signing keys/expiry timestamps are
not part of the protocol. Key rotation retries use fresh blinding randomness.

Tickets are bearer credentials. A willing member can share one; single-use is
not a guarantee that the redeemer is the original member. Group removal can take
up to 12 hours to take effect, plus Core staleness. Core checks are authoritative
only when issuing tickets, not when redeeming them. A Core outage therefore does
not terminate already authorized connections or invalidate spare tickets.

Hub keeps at most three unused tickets per cached relay batch, in account-scoped
memory. After initial redemption two spares remain for fast reconnection. It
obtains a new batch when exhausted or near expiry, coalesces simultaneous requests,
and renews live connections five minutes before expiry without replacing the
connection. Failed temporary renewals retry while the existing grant remains
valid. Logout clears tickets, in-flight state and relay connections.

## Persistence and bounds

`tickets.db` is a mode-0600 bbolt database in the persistent relay state directory.
It stores hourly signing keys, spent-ticket hashes, hourly issuance counts keyed
by hashed account, and a clock high-water mark. Redemption commits a spent marker
with normal synchronous durability **before** forwarding is permitted. Duplicate
redemption fails even concurrently or after a restart. Expired records are
pruned; live spent/quota records each have a 100,000-entry cap. Do not delete or
restore an older database while retaining ticket-signing keys. Keep the Docker
state volume when upgrading. Backups/restores are operator-trusted operations.

Each account can obtain 24 tickets per UTC hour (batches of up to three). This
limits issuance, not anonymous per-account concurrent usage. Forwarding is capped
at 256 globally by default, eight tunnels per redeemed ticket (per IP in public
mode), 512 outer connections globally and 32 per source IP. Restricted
unauthorized connections expire after 15 seconds. Reticulum has 64 active
authorization links, eight concurrent handler requests, an approximately 9 KiB
request limit, 30-second link lifetime and 256 pending one-minute challenges.
Core requests, caches, native pools, and Hub issuance requests are also bounded.

Connection deadlines use monotonic timers. A detected backwards jump across an
hour boundary fails new ticket operations closed, including after a restart.
Keep both clocks synchronized; this is not a protocol for arbitrarily wrong
system clocks.

## Privacy boundary

This design assumes the Reticulum authorization route hides the user's IP.
Blind signatures prevent a direct issuance-token-account match, **not traffic
analysis**. The same operator can observe issuance/redemption timing; a tiny
group or a single active member may be identifying. Shared public key
commitments reduce per-user key tagging, but signed announcements are not a
global transparency log and do not prevent a malicious relay from equivocating.
A malicious operator can also selectively refuse issuance. No complete-anonymity
claim is made. Local administration, packet capture, logging changes or collusion
with other services are outside the cryptographic unlinkability guarantee.

## Discovery and selection

Restricted relays publish signed binary advertisements containing the full
Reticulum service public identity and current ticket-key commitment, alongside
IP/port, TLS pin/name, group IDs and a ten-minute lease. Refresh is every two
minutes and on discovery queries. The stable service destination is also
announced for encrypted Links. No account or member list is advertised. Even
16 maximum-size group IDs and IPv6 fit the 316-byte budget with the default
name. Public relay advertisements omit the ticket authorization metadata.

Hub prefers prepared connections, public/matching-group candidates, then unknown
membership. Selection is coalesced and hedged after 300 ms, with up to two
candidates active per selection and six per pass, within a 60-second cold-path
budget. Tickets are obtained before opening an unauthenticated QUIC connection.
Service rejections remain distinct from relay failures; no direct-to-service
fallback is added.

## Verification

- `go test -race ./...`
- `python3 -m unittest discover -s scripts -p 'test_masque_discovery_codec.py'`
- Set `RELAY_TEST_BINARY`, `HUB_SIDECAR_TEST_BINARY`, and
  `HUB_BRIDGE_TEST_PATH` (the path to Hub's `presence_bridge.py`), then run
  `python3 -m unittest discover -s scripts -p 'test_hub_sidecar_access.py'`.
  This test uses the actual Hub Python handler, two isolated loopback Reticulum
  instances, real relay/sidecar binaries, generated accounts, and a mock Core.
  It checks issuance, nonmembership, forwarding, spare tickets, logout and
  restart replay.

Local tests do not establish cross-network UDP reachability or replace a macOS
wallet/discovery smoke test.

Protocol references: [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html),
[Privacy Pass architecture](https://www.rfc-editor.org/rfc/rfc9576.html).
