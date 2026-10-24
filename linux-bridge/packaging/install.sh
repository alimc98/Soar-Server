#!/usr/bin/env bash
# Install the WhiteDNS Linux bridge on Ubuntu/Debian.
# Run as root:  sudo bash install.sh 'soar://...'
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVICE=whitedns-bridge
CONFIG_DIR=/etc/whitedns-bridge
PROFILE_FILE=$CONFIG_DIR/profile
ENV_FILE=$CONFIG_DIR/bridge.env
OUTBOUND_FILE=$CONFIG_DIR/3x-ui-outbound.json
BINARY=/usr/local/bin/whitedns-bridge

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  die "run this installer as root (sudo)"
fi
if ! command -v systemctl >/dev/null 2>&1; then
  die "systemd is required (Ubuntu/Debian server)"
fi
if [[ ! -r /etc/os-release ]]; then
  die "cannot identify this Linux distribution"
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [[ ${1:-} == "--uninstall" ]]; then
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE.service" "$BINARY"
  systemctl daemon-reload
  say "Service and binary removed. Configuration kept in $CONFIG_DIR."
  say "Delete it with: rm -rf $CONFIG_DIR"
  exit 0
fi

DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BIN_SOURCE=${WHITEDNS_BRIDGE_BINARY:-}
if [[ -z "$BIN_SOURCE" ]]; then
  for candidate in "$DIR/whitedns-bridge-linux-$ARCH" "$DIR/whitedns-bridge" "$DIR/bin/whitedns-bridge-linux-$ARCH"; do
    if [[ -f "$candidate" ]]; then
      BIN_SOURCE=$candidate
      [[ -x "$BIN_SOURCE" ]] || chmod 0755 "$BIN_SOURCE" || true
      break
    fi
  done
fi
if [[ -z "$BIN_SOURCE" || ! -f "$BIN_SOURCE" || ! -x "$BIN_SOURCE" ]]; then
  die "bridge binary not found next to this script; extract the release tarball and rerun"
fi

PROFILE=${1:-}
if [[ -z "$PROFILE" ]]; then
  say "Paste the account's direct soar:// link, or an HTTPS subscription URL."
  say "A direct link works even when the panel is unreachable during a blackout."
  read -r -p "Profile: " PROFILE
fi
[[ -n "$PROFILE" ]] || die "a profile link is required"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$PROFILE" > "$tmp/profile"
chmod 600 "$tmp/profile"
say "Validating profile..."
if ! "$BIN_SOURCE" -validate -profile-file "$tmp/profile"; then
  die "profile validation failed; use the direct soar:// link from the panel"
fi

read -r -p "Require a local SOCKS5 password for 3x-ui? [Y/n]: " WANT_AUTH
SOCKS_USER=""
SOCKS_PASS=""
if [[ ! "$WANT_AUTH" =~ ^[Nn] ]]; then
  SOCKS_USER=whitedns
  SOCKS_PASS=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  say "A random local SOCKS5 password will be generated."
else
  say "WARNING: SOCKS5 authentication is disabled; any local process can use the tunnel."
fi

if ! getent group whitedns >/dev/null 2>&1; then
  groupadd --system whitedns
fi
if ! id whitedns >/dev/null 2>&1; then
  useradd --system --gid whitedns --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin whitedns
fi

systemctl stop "$SERVICE" 2>/dev/null || true
install -d -m 0750 -o root -g whitedns "$CONFIG_DIR"
install -m 0755 "$BIN_SOURCE" "$BINARY"
install -m 0640 -o root -g whitedns "$tmp/profile" "$PROFILE_FILE"
install -m 0644 "$DIR/whitedns-bridge.service" "/etc/systemd/system/$SERVICE.service"

{
  printf 'WHITEDNS_LOG_LEVEL=info\n'
  if [[ -n "$SOCKS_USER" ]]; then
    printf 'WHITEDNS_SOCKS_USER=%s\n' "$SOCKS_USER"
    printf 'WHITEDNS_SOCKS_PASS=%s\n' "$SOCKS_PASS"
  fi
} > "$ENV_FILE"
chown root:whitedns "$ENV_FILE"
chmod 0640 "$ENV_FILE"

if [[ -n "$SOCKS_USER" ]]; then
  cat > "$OUTBOUND_FILE" <<EOF
{
  "tag": "whitedns-bridge",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "127.0.0.1",
        "port": 10886,
        "users": [{ "user": "$SOCKS_USER", "pass": "$SOCKS_PASS" }]
      }
    ]
  }
}
EOF
else
  cat > "$OUTBOUND_FILE" <<'EOF'
{
  "tag": "whitedns-bridge",
  "protocol": "socks",
  "settings": {
    "servers": [{ "address": "127.0.0.1", "port": 10886 }]
  }
}
EOF
fi
chown root:whitedns "$OUTBOUND_FILE"
chmod 0640 "$OUTBOUND_FILE"

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  say "Service did not stay active. Recent logs:"
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "installation failed"
fi

say ""
say "WhiteDNS bridge is running on 127.0.0.1:10886."
say "3x-ui outbound JSON (also saved in $OUTBOUND_FILE):"
say ""
cat "$OUTBOUND_FILE"
say ""
say "Next: 3x-ui -> Xray Configs -> Outbounds -> Add Outbound -> socks,"
say "paste the JSON, then route the desired traffic through tag whitedns-bridge."
say ""
say "Health:   systemctl status $SERVICE --no-pager"
say "Logs:     journalctl -u $SERVICE -f"
say "Restart:  systemctl restart $SERVICE"
say "Uninstall: sudo bash install.sh --uninstall"
say ""
say "The SOCKS port is loopback-only. Do not expose it to the internet."
