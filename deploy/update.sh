#!/usr/bin/env bash
# Update a hand-installed relay (deploy/README.md layout) to this repository's latest commit, with
# a backup of its data and an automatic rollback if it does not come back healthy on the new build.
#
#   sudo bash /opt/sezi-server/deploy/update.sh
#
# The relay is stopped only for the backup and the restart — about two seconds. Everything that
# can take long (the git pull, a new workerd download) happens first, while the relay runs: it
# read its config and code when it started, so changing the files under it changes nothing until
# the restart. Clients ride the gap: they reconnect within a second and resend what was not acked.
#
# Environment (optional): SEZI_DIR (/opt/sezi-server), SEZI_DATA (/var/lib/sezi),
# SEZI_UNIT (sezi-relay), SEZI_PORT (8788).
set -uo pipefail

SRV="${SEZI_DIR:-/opt/sezi-server}"
DATA="${SEZI_DATA:-/var/lib/sezi}"
UNIT="${SEZI_UNIT:-sezi-relay}"
PORT="${SEZI_PORT:-8788}"
ST="$DATA/state"
WORKERD_LINK="$DATA/.local/sezi-workerd/current"
TS=$(date +%Y%m%d-%H%M%S)
BK="$DATA/backup-pre-update-$TS.tar"

[ "$(id -u)" = 0 ] || { echo "run as root (sudo): it stops and starts $UNIT" >&2; exit 1; }
as_sezi() { sudo -u sezi -H "$@"; }
served() { curl -fsS --max-time 3 "http://127.0.0.1:$PORT/capabilities" | grep -o '"build":[0-9]*' | cut -d: -f2; }
healthy() {
  for _ in $(seq 1 30); do
    curl -fsS --max-time 3 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

OLD=$(as_sezi git -C "$SRV" rev-parse HEAD)
OLD_LOCK=$(sha256sum "$SRV/workerd/WORKERD.lock" | cut -c1-64)
OLD_WORKERD=$(readlink "$WORKERD_LINK" || true)
echo "running: $OLD (build $(served || echo '?'))"

# ── 1. Prepare, while the relay runs ─────────────────────────────────────────────────────────
if ! as_sezi git -C "$SRV" pull --ff-only -q; then
  echo "pull failed — nothing was stopped or changed"; exit 1
fi
NEW=$(as_sezi git -C "$SRV" rev-parse HEAD)
if [ "$NEW" = "$OLD" ]; then echo "already up to date"; exit 0; fi
echo "new commit: $NEW"
if [ "$(sha256sum "$SRV/workerd/WORKERD.lock" | cut -c1-64)" != "$OLD_LOCK" ]; then
  echo "WORKERD.lock changed — fetching workerd"
  if ! as_sezi sh "$SRV/deploy/fetch-workerd.sh"; then
    echo "fetch-workerd failed — back to $OLD, the relay was never stopped"
    as_sezi git -C "$SRV" reset --hard -q "$OLD"
    exit 1
  fi
fi
systemctl daemon-reload

# The installed unit is a copy the owner may have adapted, so it is never overwritten here; a
# difference from this repository's is only said.
if [ -f "/etc/systemd/system/$UNIT.service" ] && ! cmp -s "$SRV/deploy/sezi-relay.service" "/etc/systemd/system/$UNIT.service"; then
  echo "note: /etc/systemd/system/$UNIT.service differs from deploy/sezi-relay.service (compare them; see deploy/README.md)"
fi

# ── 2. Stop, back up, start — the only downtime ──────────────────────────────────────────────
# The backup reads the state directory, so nothing may write it meanwhile: the relay is stopped
# (an explicit stop is never undone by `Restart=always`) and started only after the tar is done.
systemctl stop "$UNIT"
if ! tar -C "$DATA" -cf "$BK" state; then
  echo "backup failed — starting the relay on the new code without one is refused; back to $OLD"
  as_sezi git -C "$SRV" reset --hard -q "$OLD"
  [ -n "$OLD_WORKERD" ] && as_sezi ln -sfn "$OLD_WORKERD" "$WORKERD_LINK"
  systemctl start "$UNIT"
  exit 1
fi
systemctl start "$UNIT"
echo "state backup: $BK ($(du -h "$BK" | cut -f1))"

# ── 3. Check: healthy AND serving the new build, or roll back ────────────────────────────────
WANT=$(cat "$SRV/VERSION")
if healthy && [ "$(served)" = "$WANT" ]; then
  echo "OK: healthy on $NEW (build $WANT)"
  journalctl -u "$UNIT" --since "-2min" --no-pager | grep -iE "migrat|provision|error" | tail -8
  exit 0
fi

echo "FAIL: not healthy on build $WANT — rolling back to $OLD"
systemctl stop "$UNIT"
as_sezi git -C "$SRV" reset --hard -q "$OLD"
[ -n "$OLD_WORKERD" ] && as_sezi ln -sfn "$OLD_WORKERD" "$WORKERD_LINK"
rm -rf "$ST" && tar -C "$DATA" -xf "$BK"
systemctl daemon-reload
systemctl start "$UNIT"
healthy && echo "rolled back, healthy on $OLD" || echo "ROLLBACK ALSO UNHEALTHY — journalctl -u $UNIT"
journalctl -u "$UNIT" -n 30 --no-pager
exit 1
