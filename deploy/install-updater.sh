#!/usr/bin/env bash
# Install the box's update timers, so the owner can update this relay from the app with one tap
# (docs/SERVER_UPDATE_PLAN.md §4.2–4.3; decision D6: installed by default on a new install — it acts
# only on the owner's tap, and the nightly update is off until the owner turns it on in the app).
#
#   sudo bash /opt/sezi-server/deploy/install-updater.sh            install (again: keeps the token)
#   sudo bash /opt/sezi-server/deploy/install-updater.sh --remove   take the timers and the token away
#
# What it does:
#   1. A token, 32 random bytes as hex, in /etc/sezi/updater-token (root only) and as
#      SEZI_UPDATER_TOKEN in the relay's .dev.vars (its user only) — the relay answers the updater
#      only with it. Loopback alone would not do: a cloudflared tunnel also connects from 127.0.0.1.
#   2. sezi-update.service + .timer: every two minutes, deploy/sezi-update-poll.sh asks the relay
#      whether the owner asked for a build, and runs deploy/update.sh --signed for it.
#   3. sezi-update-nightly.service + .timer: about 03:30 (03:00 + up to an hour), the same script
#      with --nightly, which does something only when the owner turned automatic updates on.
#   4. Restarts the relay once (about two seconds), so it reads the token.
#
# Both services run as root — they stop and start the relay and back up its data — and run the
# scripts of this clone, which update.sh moves only to commits a signed release named. The relay
# itself cannot write the clone (its unit allows it $SEZI_DATA alone).
#
# Environment (optional): as update.sh — SEZI_DIR, SEZI_DATA, SEZI_UNIT, SEZI_PORT, SEZI_USER,
# SEZI_UNIT_DIR — and SEZI_UPDATER_TOKEN_FILE. Whatever is set here is written into the units, so
# the timers run update.sh with the same values.
set -euo pipefail

SRV="${SEZI_DIR:-/opt/sezi-server}"
DATA="${SEZI_DATA:-/var/lib/sezi}"
UNIT="${SEZI_UNIT:-sezi-relay}"
PORT="${SEZI_PORT:-8788}"
RUN_AS="${SEZI_USER:-sezi}"
UNIT_DIR="${SEZI_UNIT_DIR:-/etc/systemd/system}"
TOKEN_FILE="${SEZI_UPDATER_TOKEN_FILE:-/etc/sezi/updater-token}"
VARS="$SRV/.dev.vars"
KEY=SEZI_UPDATER_TOKEN

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
for v in "$SRV" "$DATA" "$UNIT" "$PORT" "$RUN_AS" "$TOKEN_FILE"; do
  # Every value lands in a unit file: nothing that could end a line or quote out of one.
  case "$v" in *[!A-Za-z0-9._/@-]*) echo "refused: '$v' is not a plain path or name" >&2; exit 2 ;; esac
done

# .dev.vars without the token line; the rest of the file (the claim secret, FCM, TURN …) as it was.
vars_without_token() { grep -v "^[[:space:]]*\(export[[:space:]]\+\)\?$KEY[[:space:]]*=" "$VARS" 2>/dev/null || true; }

if [ "${1:-}" = --remove ]; then
  systemctl disable --now sezi-update.timer sezi-update-nightly.timer 2>/dev/null || true
  rm -f "$UNIT_DIR"/sezi-update.service "$UNIT_DIR"/sezi-update.timer \
    "$UNIT_DIR"/sezi-update-nightly.service "$UNIT_DIR"/sezi-update-nightly.timer "$TOKEN_FILE"
  if [ -f "$VARS" ]; then
    ( umask 077; vars_without_token > "$VARS.new" ) && chown "$RUN_AS:" "$VARS.new" && mv "$VARS.new" "$VARS"
  fi
  systemctl daemon-reload
  systemctl try-restart "$UNIT" || true
  echo "the update timers are gone; the app shows the written guide again"
  exit 0
fi
[ -z "${1:-}" ] || { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ -f "$SRV/deploy/sezi-update-poll.sh" ] && [ -f "$SRV/deploy/update.sh" ] ||
  { echo "$SRV/deploy has no update.sh/sezi-update-poll.sh — not a sezi-server clone (SEZI_DIR)?" >&2; exit 1; }
for t in curl flock openssl jq; do
  command -v "$t" >/dev/null || { echo "needs $t (apt install curl util-linux openssl jq)" >&2; exit 1; }
done

# 1. The token: kept when there is one, so a second run changes nothing the relay holds.
TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE" 2>/dev/null || true)
if [ "${#TOKEN}" -lt 32 ]; then
  TOKEN=$(openssl rand -hex 32)
  install -d -m 700 "$(dirname "$TOKEN_FILE")"
  ( umask 077; printf '%s\n' "$TOKEN" > "$TOKEN_FILE" )
fi
( umask 077; { vars_without_token; echo "$KEY=$TOKEN"; } > "$VARS.new" )
chown "$RUN_AS:" "$VARS.new"
mv "$VARS.new" "$VARS"

# 2–3. The units.
env_lines="Environment=SEZI_DIR=$SRV SEZI_DATA=$DATA SEZI_UNIT=$UNIT SEZI_PORT=$PORT SEZI_USER=$RUN_AS SEZI_UPDATER_TOKEN_FILE=$TOKEN_FILE"
cat > "$UNIT_DIR/sezi-update.service" <<EOF
[Unit]
Description=Sezi relay: run the update its owner asked for in the app
After=$UNIT.service

[Service]
Type=oneshot
$env_lines
ExecStart=/bin/bash $SRV/deploy/sezi-update-poll.sh
EOF
cat > "$UNIT_DIR/sezi-update.timer" <<'EOF'
[Unit]
Description=Ask the Sezi relay every two minutes whether its owner asked for an update

[Timer]
OnActiveSec=1min
OnUnitInactiveSec=2min

[Install]
WantedBy=timers.target
EOF
cat > "$UNIT_DIR/sezi-update-nightly.service" <<EOF
[Unit]
Description=Sezi relay: the nightly update, when its owner turned it on in the app
After=$UNIT.service

[Service]
Type=oneshot
$env_lines
ExecStart=/bin/bash $SRV/deploy/sezi-update-poll.sh --nightly
EOF
cat > "$UNIT_DIR/sezi-update-nightly.timer" <<'EOF'
[Unit]
Description=The Sezi relay's nightly update check (does nothing unless turned on in the app)

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sezi-update.timer sezi-update-nightly.timer
# 4. The relay reads its environment at start.
systemctl try-restart "$UNIT"
echo "installed: sezi-update.timer (every 2 min) and sezi-update-nightly.timer (about 03:30)."
if ! grep -qs "$KEY" "$SRV/current/workerd/config.capnp"; then
  echo "note: the build running here does not read $KEY yet; the app offers the update once a"
  echo "      build that does runs (sudo bash $SRV/deploy/update.sh)."
fi
