#!/usr/bin/env bash
# Install the box's update timers, so the owner can update this relay from the app with one tap
# (docs/SERVER_UPDATE_PLAN.md §4.2–4.3; decision D6: installed by default on a new install — it acts
# only on the owner's tap, and the nightly update is off until the owner turns it on in the app).
#
#   sudo bash /opt/sezi-server/deploy/install-updater.sh            install (again: keeps the token)
#   sudo bash /opt/sezi-server/deploy/install-updater.sh --remove   take the timers, the token and the
#                                                                   root copy away
#
# What it does:
#   1. A token, 32 random bytes as hex, in /etc/sezi/updater-token (root only) and as
#      SEZI_UPDATER_TOKEN in the relay's .dev.vars (its user only) — the relay answers the updater
#      only with it. Loopback alone would not do: a cloudflared tunnel also connects from 127.0.0.1.
#   2. Root's own copy of the updater in $SEZI_UPDATER_DIR (/usr/local/lib/sezi-updater, root:root,
#      0755 directories, 0755 scripts, 0644 keys): update.sh, sezi-update-poll.sh and
#      release-keys/, taken from the deploy/ directory this script is run from.
#   3. sezi-update.service + .timer: every two minutes, the root copy's sezi-update-poll.sh asks the
#      relay whether the owner asked for a build, and runs the root copy's update.sh --signed for it.
#   4. sezi-update-nightly.service + .timer: about 03:30 (03:00 + up to an hour), the same script
#      with --nightly, which does something only when the owner turned automatic updates on.
#   5. Restarts the relay once (about two seconds), so it reads the token.
#
# Both services run as root — they stop and start the relay and back up its data. They run nothing
# from the clone: the clone, its releases and their release-keys/ belong to the relay's user, and a
# relay someone took could change them and have root run or believe the change on the next tick.
# So root runs its own copy, verifies against its own keys, and keeps its own files in
# $SEZI_UPDATER_STATE (/var/lib/sezi-updater, root only). update.sh refreshes the copy only from the
# commit a release that verified names (see refresh_updater in update.sh).
#
# THE ONE MOMENT OF TRUST is this install: the copy comes from the deploy/ this script sits in. Run
# it from a clone you just made (or one `git -C /opt/sezi-server status` and `log` show untouched).
# Running it again moves an install from before the root copy onto it (its units ran the clone's
# poll script), and refreshes the copy from this clone again.
#
# Environment (optional): as update.sh — SEZI_DIR, SEZI_DATA, SEZI_UNIT, SEZI_PORT, SEZI_USER,
# SEZI_UNIT_DIR, SEZI_UPDATER_DIR, SEZI_UPDATER_STATE — and SEZI_UPDATER_TOKEN_FILE. Whatever is set
# here is written into the units, so the timers run update.sh with the same values. SEZI_UPDATER_DIR
# and SEZI_UPDATER_STATE must be on paths only root can write, every directory up to /.
set -euo pipefail

SRV="${SEZI_DIR:-/opt/sezi-server}"
DATA="${SEZI_DATA:-/var/lib/sezi}"
UNIT="${SEZI_UNIT:-sezi-relay}"
PORT="${SEZI_PORT:-8788}"
RUN_AS="${SEZI_USER:-sezi}"
UNIT_DIR="${SEZI_UNIT_DIR:-/etc/systemd/system}"
TOKEN_FILE="${SEZI_UPDATER_TOKEN_FILE:-/etc/sezi/updater-token}"
UPD="${SEZI_UPDATER_DIR:-/usr/local/lib/sezi-updater}"
UST="${SEZI_UPDATER_STATE:-/var/lib/sezi-updater}"
HERE=$(cd "$(dirname "$0")" && pwd)
VARS="$SRV/.dev.vars"
KEY=SEZI_UPDATER_TOKEN

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
for v in "$SRV" "$DATA" "$UNIT" "$PORT" "$RUN_AS" "$TOKEN_FILE" "$UPD" "$UST"; do
  # Every value lands in a unit file: nothing that could end a line or quote out of one.
  case "$v" in *[!A-Za-z0-9._/@-]*) echo "refused: '$v' is not a plain path or name" >&2; exit 2 ;; esac
done
for v in "$UPD" "$UST"; do
  # Root's own directories, removed whole by --remove: an absolute path two levels deep at least.
  case "$v" in /?*/?*) ;; *) echo "refused: '$v' is not a directory of its own (/x/y at least)" >&2; exit 2 ;; esac
done

# write_vars [token]: .dev.vars without the token line — the rest (the claim secret, FCM, TURN …)
# as it was — plus the new line when a token is given. Read and written as $RUN_AS: the file and its
# directory are that user's, and root never reads or writes through a path it could have linked.
# The token goes in on stdin, never on a command line.
write_vars() {
  printf '%s\n' "${1:-}" | sudo -u "$RUN_AS" -H sh -c '
    umask 077; v=$1; key=$2; read -r tok
    { grep -v "^[[:space:]]*\(export[[:space:]]\+\)\?$key[[:space:]]*=" "$v" 2>/dev/null
      [ -z "$tok" ] || echo "$key=$tok"; } > "$v.new" && mv "$v.new" "$v"' sh "$VARS" "$KEY"
}

if [ "${1:-}" = --remove ]; then
  systemctl disable --now sezi-update.timer sezi-update-nightly.timer 2>/dev/null || true
  rm -f "$UNIT_DIR"/sezi-update.service "$UNIT_DIR"/sezi-update.timer \
    "$UNIT_DIR"/sezi-update-nightly.service "$UNIT_DIR"/sezi-update-nightly.timer "$TOKEN_FILE"
  rm -rf "$UPD"
  [ ! -f "$VARS" ] || write_vars
  systemctl daemon-reload
  systemctl try-restart "$UNIT" || true
  echo "the update timers and $UPD are gone; the app shows the written guide again"
  echo "($UST keeps the state backups and the accepted release seq; remove it by hand if you want)"
  exit 0
fi
[ -z "${1:-}" ] || { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ -d "$SRV/.git" ] || { echo "$SRV is not a sezi-server clone (SEZI_DIR)?" >&2; exit 1; }
[ -f "$HERE/sezi-update-poll.sh" ] && [ -f "$HERE/update.sh" ] && ls "$HERE"/release-keys/*.pem >/dev/null 2>&1 ||
  { echo "$HERE has no update.sh/sezi-update-poll.sh/release-keys — run the deploy/ of a sezi-server clone" >&2; exit 1; }
for t in curl flock openssl jq git; do
  command -v "$t" >/dev/null || { echo "needs $t (apt install curl util-linux openssl jq)" >&2; exit 1; }
done

# 1. The token: kept when there is one, so a second run changes nothing the relay holds.
TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE" 2>/dev/null || true)
if [ "${#TOKEN}" -lt 32 ]; then
  TOKEN=$(openssl rand -hex 32)
  install -d -m 700 "$(dirname "$TOKEN_FILE")"
  ( umask 077; printf '%s\n' "$TOKEN" > "$TOKEN_FILE" )
fi
write_vars "$TOKEN"

# 2. Root's copy: staged beside it, then moved in, so a timer never finds half of it.
install -d -m 0755 "$UPD"
mkdir -p "$UST" && chmod 0700 "$UST"
S="$UPD/.staging"
rm -rf "$S"
install -d -m 0755 "$S" "$S/release-keys"
install -m 0755 "$HERE/update.sh" "$HERE/sezi-update-poll.sh" "$S/"
install -m 0644 "$HERE"/release-keys/*.pem "$S/release-keys/"
chown -R root:root "$UPD"
mv -f "$S/update.sh" "$S/sezi-update-poll.sh" "$UPD/"
rm -rf "$UPD/.old-keys"
[ ! -d "$UPD/release-keys" ] || mv "$UPD/release-keys" "$UPD/.old-keys"
mv "$S/release-keys" "$UPD/release-keys"
# Not from a verified commit: the next signed run replaces it with the newest release's own.
rm -rf "$UPD/.old-keys" "$S" "$UPD/.sezi-commit"

# 3–4. The units.
env_lines="Environment=SEZI_DIR=$SRV SEZI_DATA=$DATA SEZI_UNIT=$UNIT SEZI_PORT=$PORT SEZI_USER=$RUN_AS SEZI_UPDATER_TOKEN_FILE=$TOKEN_FILE SEZI_UPDATER_DIR=$UPD SEZI_UPDATER_STATE=$UST"
cat > "$UNIT_DIR/sezi-update.service" <<EOF
[Unit]
Description=Sezi relay: run the update its owner asked for in the app
After=$UNIT.service

[Service]
Type=oneshot
$env_lines
ExecStart=/bin/bash $UPD/sezi-update-poll.sh
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
ExecStart=/bin/bash $UPD/sezi-update-poll.sh --nightly
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
# 5. The relay reads its environment at start.
systemctl try-restart "$UNIT"
echo "installed: sezi-update.timer (every 2 min) and sezi-update-nightly.timer (about 03:30),"
echo "           running root's copy in $UPD."
if ! grep -qs "$KEY" "$SRV/current/workerd/config.capnp"; then
  echo "note: the build running here does not read $KEY yet; the app offers the update once a"
  echo "      build that does runs (sudo bash $UPD/update.sh)."
fi
