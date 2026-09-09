# Qortal MASQUE Relay

Run a community relay for Qortal's private QUIC transport.

This is a standalone, application-neutral HTTP/3 CONNECT-UDP service. It runs
separately from Qortal Hub and from the UDP services it forwards to. The relay
advertises itself through Reticulum, allowing Hubs to discover it without a
central relay directory or DNS-based discovery.

## Quick start

These steps assume a Linux host with Docker and a router that supports UPnP.

1. Open the project:

   ```bash
   cd /path/to/qortal-masque-relay
   ```

2. Edit `relay-access.json`. To restrict use to members of one or more Qortal
   groups:

   ```json
   {
     "mode": "groups",
     "allowed_group_ids": [100],
     "core_url_bases": ["https://ext-node.qortal.link"]
   }
   ```

   Replace `100` with a positive numeric group ID. To allow everyone
   instead, use:

   ```json
   {
     "mode": "public",
     "allowed_group_ids": [],
     "core_url_bases": []
   }
   ```

3. If UFW is active, allow the public UDP port:

   ```bash
   sudo ufw status
   sudo ufw allow 47322/udp
   ```

   Run the second command only when UFW reports `Status: active`.

4. Build and start the relay:

   ```bash
   docker compose up -d --build
   ```

5. Verify startup and Reticulum discovery:

   ```bash
   docker compose ps
   docker compose logs --tail=100 relay
   ```

   A healthy startup reports `MASQUE relay availability announced through
   Reticulum`.

If automatic UPnP fails, follow [Manual port forwarding](#manual-port-forwarding).

No `.env` file or backend registration is needed for this setup. Authorized
users can connect to public backend endpoints automatically.

## How it fits together

```text
Qortal Hub             MASQUE relay          Public UDP service
    |                        |                         |
    |-- outer HTTP/3 ------->|                         |
    |   CONNECT-UDP          |                         |
    |                        |-- forwarded UDP ------->|
    |<================ protected inner QUIC =========>|
```

The relay:

- Accepts HTTP/3 CONNECT-UDP on a public UDP port.
- Forwards authorized users' traffic to public UDP endpoints without backend
  approval or registration.
- Announces its endpoint, access policy, and pinned TLS certificate through
  Reticulum.
- Can be public or restricted to members of selected Qortal groups.
- Terminates the outer MASQUE connection but cannot decrypt the protected inner
  QUIC connection between Hub and the destination service.

The relay does see the connecting IP address, selected UDP target, traffic
timing, and packet sizes. Read [Security and privacy](#security-and-privacy)
before operating one.

## Requirements

- Linux with Docker Engine and Docker Compose v2.
- A public IPv4 or IPv6 address that can receive one UDP port.
- UPnP support or a manual UDP port forward.
- Correct system time for restricted-access ticket validation.

Docker host networking is used so the relay can create UPnP mappings and reach
loopback services when explicitly configured. Targets use literal IP addresses
and ports; hostnames are not accepted. Public endpoints work by default.
Private and loopback services require an optional exact exception.

## Access policy

`relay-access.json` controls who may use the relay.

### Group-restricted relay

```json
{
  "mode": "groups",
  "allowed_group_ids": [100, 200],
  "core_url_bases": [
    "https://ext-node.qortal.link",
    "https://backup-core.example"
  ]
}
```

- Configure 1–16 unique, positive group IDs.
- Membership in any one configured group is sufficient.
- Configure 1–8 trusted Qortal Core endpoints, tried in order.
- Remote Core URLs must use HTTPS. A local Core may use HTTP.
- If membership cannot be verified, access fails closed.

### Public relay

```json
{
  "mode": "public",
  "allowed_group_ids": [],
  "core_url_bases": []
}
```

Public mode does not perform membership queries. It can consume substantially
more bandwidth, so monitor capacity and usage.

The full authorization protocol, anonymous-ticket behavior, limits, and threat
model are documented in [ACCESS.md](ACCESS.md).

## Public reachability

The default public endpoint is UDP `47322`. This is **UDP, not TCP**.

### Automatic UPnP

With the default settings, the relay asks the router to map UDP `47322`, reads
the router's public IP, and renews the mapping. No public address needs to be
entered manually.

```dotenv
QORTAL_MASQUE_PUBLIC_ADDRESS=
QORTAL_MASQUE_UPNP=true
```

### Manual port forwarding

Use this when UPnP is unavailable:

1. Forward UDP `47322` on the router to UDP `47322` on the relay host.
2. Allow inbound UDP `47322` in the host and provider firewalls.
3. Copy `.env.example` to `.env`, set the actual public endpoint, and disable UPnP:

   ```dotenv
   QORTAL_MASQUE_PUBLIC_ADDRESS=203.0.113.10:47322
   QORTAL_MASQUE_UPNP=false
   ```

Do not use the documentation address above unchanged. Set the host's actual
public IP. Private addresses, domain names, and carrier-grade NAT addresses are
not valid public endpoints.

If the host is behind CGNAT and cannot receive a port forward, it cannot run a
publicly reachable relay from that connection.

### Ubuntu/UFW firewall

Check whether UFW is enabled:

```bash
sudo ufw status
```

If it reports `Status: active`, allow the configured relay port:

```bash
sudo ufw allow 47322/udp
```

Cloud hosts may also have a provider firewall or security group that must allow
the same inbound UDP port.

## Verify the relay

Check the container and recent logs:

```bash
docker compose ps
docker compose logs --tail=100 relay
```

An automatic-UPnP startup includes messages equivalent to:

```text
UPnP mapped UDP 47322; public endpoint PUBLIC_IP:47322
MASQUE relay discovery destination ...
MASQUE relay availability announced through Reticulum
```

With manual forwarding, the UPnP line is absent. The relay also prints one JSON
line containing its advertised address and TLS certificate pin.

Verify the three important layers:

1. **Process:** `docker compose ps` reports the relay as running.
2. **Discovery:** the log reports a Reticulum availability announcement. A
   `discovery query received` followed by `discovery response sent` confirms a
   Hub requested relays and received the response.
3. **Forwarding:** successful use produces `MASQUE CONNECT-UDP request accepted
   for target ...`, showing the requested destination. This confirms tunnel
   acceptance; a successful application exchange confirms end-to-end delivery.

Most web port checkers test TCP and will incorrectly report this UDP/QUIC
service as closed. Test from a current Qortal Hub on another network.

## Configuration reference

Optional local settings belong in `.env`, which Git ignores. `.env.example`
serves as a template. You do not need to copy it for the default UPnP setup.

| Variable | Default | Meaning |
| --- | --- | --- |
| `QORTAL_MASQUE_ALLOWED_TARGETS` | empty; optional | Exact private/loopback UDP exceptions, separated by commas |
| `QORTAL_MASQUE_RELAY_PORT` | `47322` | Local and advertised UDP port |
| `QORTAL_MASQUE_PUBLIC_ADDRESS` | empty | Manual literal `IP:PORT`; empty uses UPnP |
| `QORTAL_MASQUE_UPNP` | `true` | Automatically create and maintain the UDP mapping |
| `QORTAL_MASQUE_SERVER_NAME` | `qortal-masque-relay` | Logical name covered by the pinned certificate |
| `QORTAL_MASQUE_MAX_SESSIONS` | `256` | Global simultaneous CONNECT-UDP sessions |
| `QORTAL_MASQUE_RNS_CONFIG` | `./reticulum.conf` | Reticulum configuration mounted into the container |

Public backend endpoints are permitted automatically after user authorization.
The relay does not validate or register backends. Private and loopback
destinations are blocked unless the operator intentionally adds an exact
exception, for example for services on the relay host:

```dotenv
QORTAL_MASQUE_ALLOWED_TARGETS=127.0.0.1:9000,192.168.1.25:9001
```

Adding exceptions does not restrict access to public endpoints. Only add the
specific local services you intend relay users to reach. Multicast, unspecified,
link-local, and other non-public destinations remain blocked.

The bundled Reticulum configuration tries a local Qortal Hub and the configured
public Qortal gateways. The public gateways allow discovery to continue when
the local Hub is closed.

## Everyday operation

View live logs:

```bash
docker compose logs -f relay
```

Reload only `relay-access.json`:

```bash
docker compose restart relay
```

Apply code changes:

```bash
docker compose up -d --build
```

Apply `.env` or Compose changes:

```bash
docker compose up -d --force-recreate
```

These operations interrupt active tunnels. Schedule changes when possible.

Stop the relay:

```bash
docker compose down
```

Docker volumes preserve the TLS identity, Reticulum identity, and anonymous
ticket database. Do not use `docker compose down -v` during normal operation or
upgrades.

## Troubleshooting

### `automatic public UDP mapping unavailable`

The router did not provide a usable UPnP mapping. Configure a manual UDP port
forward and set the manual public address in `.env`. Also check for CGNAT.

### Container repeatedly restarts

Run `docker compose logs --tail=200 relay`. Common causes are malformed JSON,
an invalid endpoint, a port already in use, or failed
Reticulum connectivity.

### Hub reports `MASQUE_RELAY_UNAVAILABLE`

Confirm the relay is announcing through Reticulum, its public UDP port is
reachable, its system clock is correct, and Hub can receive Reticulum
advertisements.

### Hub reports `RELAY_ACCESS_DENIED`

The authenticated Qortal account is not a member of any configured group.
Confirm the group IDs. Core outages normally produce a membership-unavailable
error rather than a denial.

### Hub reports `MASQUE_TUNNEL_FAILED` or `TRANSPORT_ERROR`

Check public UDP reachability and relay logs. If the target was accepted,
confirm that the destination UDP service is running and reachable from the
relay host.

### `target ... is not permitted`

The client requested a blocked destination. Public endpoints need no entry in
`QORTAL_MASQUE_ALLOWED_TARGETS`. If this is an intentionally supported private
or loopback service, add only its exact IP and port as an exception.

## Security and privacy

- The relay terminates outer MASQUE TLS but only forwards the protected inner
  QUIC packets. It does not receive the inner TLS keys or plaintext payload.
- Clients pin the exact relay TLS certificate fingerprint advertised through
  Reticulum. Public Web PKI, HTTPS discovery, and DNS discovery are not needed.
- In group mode, account ownership and membership are proved over an encrypted
  Reticulum link. The subsequent IP-visible QUIC connection presents an
  anonymous, blind-signed, single-use ticket rather than a Qortal address.
- The relay sees connecting IP addresses, selected targets, traffic timing, and
  packet sizes. Blind tickets prevent a direct account-to-QUIC record but cannot
  prevent timing correlation or identification in a very small group.
- Membership is checked when tickets are issued. Tickets last approximately
  11–12 hours, so removing a member is not instantaneous.
- Configured Core endpoints learn the Qortal addresses checked for membership
  and are trusted to answer accurately.
- Persistent identity keys and the ticket database are stored in the
  `relay-data` volume. Protect Docker access and host backups.
- Public UDP endpoints are reachable by admitted users. User authorization and
  capacity limits apply; the relay does not prove ownership of destinations.
  Private and loopback endpoints require exact operator exceptions.

See [ACCESS.md](ACCESS.md) for protocol-level security details and resource
limits.

## Development checks

```bash
go test -race ./...
python3 -m unittest discover -s scripts -p 'test_masque_discovery_codec.py'
```

The cross-project integration test requires `RELAY_TEST_BINARY`,
`HUB_SIDECAR_TEST_BINARY`, and `HUB_BRIDGE_TEST_PATH`. See
[ACCESS.md](ACCESS.md#verification).
