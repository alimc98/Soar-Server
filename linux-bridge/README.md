# WhiteDNS Linux bridge

A headless Linux client for the WhiteDNS Soar tunnel. It runs on an Iranian
Ubuntu/Debian server, connects out through DNS to the WhiteDNS server, and
exposes a loopback SOCKS5 outbound for 3x-ui/Xray.

```
VLESS clients
    |
    v
3x-ui / Xray on the Iran server
    |  outbound: socks 127.0.0.1:10886
    v
whitedns-bridge  (Soar client, this package)
    |  authenticated DNS tunnel
    v
WhiteDNS server abroad
    |
    v
Internet
```

This is different from the panel's built-in SOCKS5 page. That listener runs on
the foreign server and requires direct reachability from 3x-ui. During a
nationwide blackout the Iran server cannot reach it. The bridge solves that by
terminating the Soar tunnel on the Iran server and handing 3x-ui a local
outbound.

## Requirements

- Ubuntu 22.04/24.04/26.04 or Debian 12/13, x86_64 or arm64, systemd.
- A WhiteDNS account whose profile uses the Soar engine.
- A direct `soar://` profile link, or an HTTPS subscription URL that is
  reachable **at install time**. Keep a direct link for blackout provisioning.
- The account's allowed destination ports (default 80/443) and quota apply.

## Install

Extract the release tarball and pass the direct profile link:

```bash
tar -xzf whitedns-bridge-0.1.0-linux-amd64.tar.gz
cd whitedns-bridge-0.1.0-linux-amd64
sudo bash install.sh 'soar://...'
```

The installer:

1. validates the profile (and fetches a subscription URL if one is used);
2. creates a system user and installs a systemd service;
3. generates a random local SOCKS5 password unless you decline;
4. starts the bridge on `127.0.0.1:10886`;
5. writes the ready-to-paste 3x-ui outbound to
   `/etc/whitedns-bridge/3x-ui-outbound.json` and prints it.

Useful commands:

```bash
systemctl status whitedns-bridge --no-pager
journalctl -u whitedns-bridge -f
systemctl restart whitedns-bridge
sudo bash install.sh --uninstall
```

The profile is stored in `/etc/whitedns-bridge/profile`; local SOCKS
credentials are in `/etc/whitedns-bridge/bridge.env`. Both are root-readable
and group-readable by `whitedns` only.

## 3x-ui setup

Add an outbound under **Xray Configs → Outbounds → Add Outbound → socks**:

```json
{
  "tag": "whitedns-bridge",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "127.0.0.1",
        "port": 10886,
        "users": [{ "user": "whitedns", "pass": "GENERATED_PASSWORD" }]
      }
    ]
  }
}
```

Then route the traffic that must leave through the tunnel to `whitedns-bridge`.
A typical layout is:

- VLESS inbound on the Iran server for users (TCP; do not enable UDP);
- routing rule for that inbound's tag → `whitedns-bridge`;
- a direct/freedom outbound remains available for Iranian destinations;
- keep Xray's DNS resolver on a direct/domestic path. Do not send UDP DNS
  queries through the bridge; it only carries TCP.

The bridge only supports SOCKS5 **CONNECT/TCP**. UDP, QUIC and UDP ASSOCIATE do
not work. VLESS itself can run over TCP; route only TCP through the bridge.

## Why not expose the SOCKS port?

The bridge deliberately refuses a non-loopback listen address. SOCKS5 does not
encrypt its username/password, and this listener is meant for a local 3x-ui
process. If 3x-ui is on another machine, forward the port over WireGuard or SSH;
do not open it to the internet.

## Provisioning before a blackout

The bridge needs the tunnel identity (zone and public key) and bootstrap
resolvers. It does not need the panel to be reachable after installation. Use a
direct `soar://` link, install and test the bridge while normal connectivity
exists, then keep the service enabled. A subscription URL may work during
installation but will not refresh while the panel is unreachable; that is fine
because the tunnel identity does not change when the account is edited. The
exception is tunnel-key rotation: reinstall the new profile after rotating it,
because the old public key stops working.

If the tunnel never becomes ready, the configured DNS resolvers may be blocked
on the Iranian network. Override them with resolvers that answer from that
server while keeping discovery enabled:

```bash
sudo systemctl edit whitedns-bridge
# [Service]
# Environment=WHITEDNS_RESOLVERS=10.202.10.202,10.202.10.102
sudo systemctl restart whitedns-bridge
```

Use resolvers that actually carry the tunnel; a resolver that answers normal
DNS but drops tunnel-shaped queries will not work. The bundled `ir.txt` and
`global.txt` discovery candidates are tried when `discovery` is enabled in the
profile.

## Build from source

Go 1.25+ is required:

```bash
make test
make package
```

`make package` cross-compiles Linux amd64 and arm64 tarballs under `dist/`. Each
tarball contains the binary, installer, systemd unit, documentation, the
project license/NOTICE, and a `licenses/` directory with the vendored Soar
license, change notes and resolver-data notice. The vendored `third_party/soar`
is the WhiteDNS-patched Soar v0.2.3 client used by WhiteDNS Desktop.

## Configuration flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-profile` | `$WHITEDNS_PROFILE` | direct link, HTTPS subscription, or file |
| `-profile-file` | `/etc/whitedns-bridge/profile` | file containing the link |
| `-listen` | `127.0.0.1:10886` | loopback SOCKS5 address |
| `-username`, `-password` | empty | optional local SOCKS5 auth |
| `-resolvers` | profile list | override bootstrap resolvers |
| `-max-conns` | profile `maxStreams` | local connection ceiling |
| `-dial-timeout` | profile value | destination dial timeout |
| `-check` | `true` | background authenticated-HTTPS probe |
| `-validate` | `false` | validate the profile and exit |

`WHITEDNS_PROFILE`, `WHITEDNS_PROFILE_FILE`, `WHITEDNS_SOCKS_LISTEN`,
`WHITEDNS_SOCKS_USER`, `WHITEDNS_SOCKS_PASS`, `WHITEDNS_RESOLVERS` and
`WHITEDNS_LOG_LEVEL` can be set in `/etc/whitedns-bridge/bridge.env`.

## Limits and security

- All 3x-ui users share the bridge account's quota, rate limit and stream limit.
- The panel's destination-port allowlist still applies on the foreign server.
- The bridge authenticates the server with its Ed25519 public key; the DNS
  tunnel is the encrypted transport. SOCKS credentials only protect the local
  hop.
- The listener has a 10-second handshake timeout and the profile's dial
  timeout. A full connection table returns errors instead of growing without
  bound.
- One bridge process serves one profile. Run one service per account if needed.
