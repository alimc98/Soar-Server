# WhiteDNS Soar Panel: implementation contract

The panel is a server-side addition. No Android files or wire protocol are changed.
Lantern owns the upstream Soar engine; WhiteDNS develops this management layer.
The operator workflow (sidebar, dashboard, account table, edit dialog) is inspired
by MHSanaei/3x-ui. This is original Go/HTML/CSS/JS; no GPL 3x-ui source/assets are
incorporated. System fonts avoid third-party font redistribution.

## Data path

One physical authoritative UDP socket dispatches unchanged DNS queries by account
zone to separate `soar.Serve` instances. Each account has a random label and an
independent Ed25519 key. Its label is immediately before the delegated base zone;
encoded transport labels remain unchanged. Account zones fit the existing
WhiteDNS 45-character limit. The base zone is limited to 24 ASCII characters,
leaving at least 100 bits of unpredictable label. No anonymous root-zone tunnel
exists. Root SOA answers support authoritative checks. Unknown accounts get REFUSED.

Soar sees resolver addresses, not reliable device IPs. An account is a shared
configuration identity, **not cryptographic device authentication**. A DNS observer
who learns the zone can attempt to consume that account's budget. Server keys
authenticate the server to the client; they are not user password credentials.
Do not advertise anti-sharing, distinct device counts, or subscriber identity.

Custom `Dial` enforces ports and upstream `soar.PublicOnly` on the actual resolved
destination. Keep this guard: supplying custom Dial bypasses upstream defaults.
Private destinations are overridden only by unexported integration-test wiring;
there is no production option to bypass the guard.
The systemd unit permits AF_NETLINK because Go's interface-address enumeration
needs it for that guard. Denying it makes PublicOnly fail closed for all targets;
an authenticated DNS handshake alone therefore is not a deployment health check.

## Durable accounting

bbolt transactions serialize budget reservations across all directions/streams.
Upload is committed before upstream Write and unconsumed bytes are refunded.
Download is committed after upstream Read and before returning payload to Soar.
Each accounting operation is bounded to 32 KiB, with smaller chunks under rate
limits. All traffic shares upload+download budget and aggregate rate scheduler.
This measures forwarded TCP payload, not DNS wire traffic, retransmission, or
datacenter billing. There is no unsynced periodic counter whose loss enables free
traffic. A crash can charge bounded unfinished payload conservatively. Reset
changes usage epoch; old reservations/refunds cannot charge or erase a new period.
Metadata revisions independently protect admin edits from lost updates.

Disabled/expired/exhausted clients are checked at dial and accounting operations;
reconciliation closes active runtimes immediately after admin changes and within
one second of time-based expiry. Idle sessions do not reserve quota. Rotating
zone/key closes old sessions and preserves accounting. Disconnect closes streams
but permits an enabled account to reconnect. Reset closes old sessions and starts
a new usage epoch. The rate limit is aggregate bytes/sec, not a per-device cap.

Initial limits: 512 persisted accounts, 8 sessions/account, at most 128 outbound
streams/account, and 2048 global pending+active outbound streams. These are hard
ceilings, not measured capacity promises. DNS queues are bounded and shed overload.
Per-account engine reflection limits remain enabled; a production capacity/security
review must consider aggregate DNS/handshake pressure across accounts.

## Control plane

Embedded assets require no CDN, frontend build service, external QR API or online
font. Persian RTL interface has mobile and keyboard handling, native dialogs,
explicit destructive-operation confirmation, real metrics, empty/error states,
dark/light theme. Unknown host metrics show a dash, not invented zero values.
All account names and notes are inserted as text, never HTML. CSV formula cells
are escaped. Client files use the existing `whitedns.profile` v1 schema and `soar://`.

Global `soarSettings` persist the 16 supported profile transport controls. A
missing object in a legacy database reads as the adaptive defaults;
legacy settings writes preserve saved tuning. Invalid ranges or crossed name
lengths fail before committing. The API does not accept cipher/MTU switches the
engine cannot apply. Exported links embed a snapshot: changes require reimport,
without rotating identity or changing server-side quotas. Every settings field
has a text explanation available on hover, keyboard focus and a touch button.

The CLI defaults to loopback. Public binds require TLS or an explicit
`--allow-insecure-http` choice for a test server. The wizard offers direct IP/port
HTTP and private SSH/HTTPS-proxy modes, shows the resulting URL, and preserves
the prior access mode as the rerun default. Fresh installations suggest direct
HTTP with a clear plaintext notice. A local HTTPS proxy can be explicitly trusted
only from loopback. Passwords are bcrypt cost 12. Sessions
are memory-only, expire after 12 hours, and are invalidated by restart. Cookies are
HttpOnly/SameSite Strict and Secure over HTTPS. State-changing API requests require
a session CSRF token and reject foreign Origin. Login attempts are throttled;
database/backup contain private seeds and password hashes and must remain 0600.
Sessions/CSRF/key material are not logged. Audit keeps the latest 2000 admin events,
API returns the latest 200. Browsing destinations/content are not recorded.

## Rollout

Stable standalone setup remains separate. Panel 0.3.1 is the stable default in the README,
with IPv4/amd64 support. A running standalone instance is stopped only after
typing MIGRATE, preserving its keys/config and offering rollback. Migrating root
shared profiles to individual accounts requires distributing new profile links,
with the existing profile format. The browser transport fixes require WhiteDNS
1.6.7 or newer; a server upgrade cannot replace an installed native core. Never deploy over an
existing delegated MasterDNS zone. Test on isolated ports before a production switch.

Automated checks cover authenticated HTTPS through unmodified upstream clients,
account isolation, concurrent exact quotas, restart/backup persistence, rate and
stream limits, disable/rotate, private destination protection, old-epoch isolation,
authentication/CSRF, QR generation, SOCKS5 authentication/policy/metering and
responsive browser workflows. Passing these checks does not establish reachability
on Iranian access networks; field testing on those networks remains required.

## SOCKS5 egress (0.5.0)

The panel can expose an opt-in SOCKS5 listener for a 3x-ui/Xray installation that
needs an authenticated outbound. It is an independent egress path: CONNECT is
dialed directly through `Manager.dialEgress`, not through the DNS tunnel. It is
therefore TCP-only, has no UDP ASSOCIATE, and is not a substitute for the tunnel.
The default bind is `127.0.0.1:1080`; the listener is disabled until an
administrator enables it. A remote 3x-ui host requires binding a reachable
address and restricting it with a firewall or private network.

The username is the 32-character account ID. The password is the base64url
encoding of `HMAC-SHA256(seed, "WhiteDNS SOCKS5 credential v1:<SocksEpoch>")`,
using the account's existing Ed25519 seed. It is deterministic for backups and
account edits, changes when the tunnel key is rotated, and can be revoked
independently by incrementing `SocksEpoch`. Rotation is a CSRF-checked admin
action; it closes the account's active SOCKS connections without changing tunnel
keys, profiles or subscription tokens.

Because CONNECT reuses `dialEgress`, the account's enabled/expiry/quota state,
aggregate rate, destination-port allowlist, public-destination guard, per-account
stream limit and the 2048 global stream ceiling all apply. Upload and download
payload are reserved in the same bbolt accounting path as tunnel traffic; idle
SOCKS connections do not reserve quota. Reconfiguration binds the replacement
listener before persisting settings, and a failed bind keeps the previous
listener serving and reports the error in the SOCKS status endpoint.

Resource limits are intentionally small: 512 accepted SOCKS connections, a 10 s
handshake deadline, a 20 s dial deadline, and 10 authentication failures per IP
per 5 minutes. Per-account stream limits cap how many connections one credential
can hold. The 512 ceiling also covers clients that are still negotiating, so an
unauthenticated peer can temporarily occupy slots; keep the listener on loopback
or a trusted network. The password and payload are not encrypted by SOCKS5, so a
public bind without WireGuard/IPsec/SSH forwarding exposes credentials and
traffic to any on-path observer. Never expose the port to the public internet
without an additional encrypted transport.

SOCKS settings live in the same settings record and client epochs in the same
client records as the rest of the panel. Full backups therefore include them;
restore restarts the service and rebinds the listener from the restored record.
If the saved address is already occupied at startup, the panel continues to run
and the SOCKS page reports `listening: false` with the bind error rather than
failing the whole service.

## Linux bridge for blackout conditions

The direct SOCKS5 listener above is only useful when the 3x-ui host can reach
this server's address. During a nationwide blackout that path is unavailable.
The supported topology instead runs `linux-bridge/` on the Iranian 3x-ui host:
it parses the account's `soar://` profile, runs the WhiteDNS-patched Soar
client, and exposes an unencrypted SOCKS5 listener on `127.0.0.1:10886` for the
local 3x-ui/Xray process. Xray then adds a socks outbound and routes the desired
inbound traffic through the DNS tunnel. The bridge refuses non-loopback
listeners; use SSH or WireGuard forwarding if 3x-ui is not on the same host.
It supports CONNECT/TCP only, enforces the local profile's stream count and dial
timeout, and sends all traffic through the same server-side quota, rate, port
allowlist, public-destination and accounting checks as tunnel traffic. The
profile must be provisioned before a blackout because the bridge cannot fetch a
subscription from an unreachable panel. See `linux-bridge/README.fa.md` for the
installer, systemd unit, 3x-ui JSON and rotation guidance.


## Subscriptions and interface language (0.3.0)

Two optional Bolt buckets bind independent 32-byte subscription tokens to client
IDs and index SHA-256(token) to client IDs. Account deletion removes both entries.
Read-only public GET/HEAD `/sub/<token>` routes precede the private admin prefix
without revealing it. HTTPS configuration enforces TLS and the configured host.
Responses use a single transaction snapshot of account data and current settings;
no cached profile can pin a stale tunnel key. Disabled/expired/exhausted accounts
receive 403 without profile data. Rotation is an authenticated, CSRF-checked POST
and never changes tunnel keys or accounting epochs. New backups validate both
subscription tables; legacy backups migrate lazily. See SUBSCRIPTIONS.md.

The self-hosted `i18n.js` catalog translates authored static DOM nodes once and
explicit dynamic UI strings at their creation sites. No dynamic DOM rewriting
or third-party translation service touches account names, notes, keys or input
values. The browser-local language choice selects `fa-IR`/`en-GB` formatting,
RTL/LTR layout and contextual help direction. Switching reloads the current page;
authentication remains under the existing session/cookie rules.
