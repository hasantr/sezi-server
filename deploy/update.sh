#!/usr/bin/env bash
# Update a hand-installed relay (deploy/README.md layout) — or move it to another build it can go
# back to — with a backup of its data and an automatic rollback if it does not come back healthy.
#
#   sudo bash /opt/sezi-server/deploy/update.sh                 the newest build on origin/main
#   sudo bash /opt/sezi-server/deploy/update.sh --to <build>    that build (the yyyyMMddHHmm in its
#                                                               VERSION): newer, or a kept older one
#   sudo bash /opt/sezi-server/deploy/update.sh --commit <sha>  exactly that template commit (the one
#                                                               a signed release names)
#   sudo bash /opt/sezi-server/deploy/update.sh --layout        only move an older install to the
#                                                               releases/ layout below
#
# LAYOUT. The clone stays where it was and only fetches; every build runs from its own exported tree:
#
#   /opt/sezi-server/                      the git clone: fetch, deploy/ (this script), .dev.vars
#   /opt/sezi-server/releases/<build>/     one tree per build (git archive of its commit), never edited
#   /opt/sezi-server/current -> releases/<build>     what the unit runs (ExecStart reads
#                                                    current/workerd/config.capnp)
#
# The newest SEZI_KEEP (3) releases and state backups are kept, older ones pruned, and with them the
# workerd versions no kept release names. Going back to a kept build moves `current` and restarts:
# its data stays as it is — the relay's migrations are expand-only, so the previous build runs on
# the newer schema (AGENTS.md, "Relay migrations are expand-only"). An install from before this
# layout is moved on its first run (its unit's paths are rewritten once, the old unit kept beside
# it as <unit>.service.pre-releases) — and it says so.
#
# The relay is stopped only for the backup and the restart — about two seconds. Everything that can
# take long (the fetch, the export, a new workerd download) happens first, while the relay runs.
# Clients ride the gap: they reconnect within a second and resend what was not acked.
#
# The result is also written to $SEZI_DATA/update-result.json ({to, from, ok, code, at}).
#
# Environment (optional): SEZI_DIR (/opt/sezi-server), SEZI_DATA (/var/lib/sezi), SEZI_UNIT
# (sezi-relay), SEZI_PORT (8788), SEZI_USER (sezi — the user the relay runs as and owns the clone),
# SEZI_KEEP (3), SEZI_UNIT_DIR (/etc/systemd/system).
set -uo pipefail

# Run from a copy: this file lives in the clone, which a fetch and the final fast-forward change,
# and bash reads a script while it runs it.
if [ -z "${SEZI_UPDATE_COPY:-}" ]; then
  copy=$(mktemp "${TMPDIR:-/tmp}/sezi-update.XXXXXX") || exit 1
  cp "$0" "$copy" || exit 1
  SEZI_UPDATE_COPY=$copy exec bash "$copy" "$@"
fi
trap 'rm -f "$SEZI_UPDATE_COPY"' EXIT

SRV="${SEZI_DIR:-/opt/sezi-server}"
DATA="${SEZI_DATA:-/var/lib/sezi}"
UNIT="${SEZI_UNIT:-sezi-relay}"
PORT="${SEZI_PORT:-8788}"
RUN_AS="${SEZI_USER:-sezi}"
KEEP="${SEZI_KEEP:-3}"
UNIT_FILE="${SEZI_UNIT_DIR:-/etc/systemd/system}/$UNIT.service"
ST="$DATA/state"
TS=$(date +%Y%m%d-%H%M%S)
BK="$DATA/backup-pre-update-$TS.tar"
RESULT="$DATA/update-result.json"

TO=""; COMMIT=""; LAYOUT_ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --to) TO=${2:-}; shift 2 || { echo "--to needs a build" >&2; exit 2; } ;;
    --commit) COMMIT=${2:-}; shift 2 || { echo "--commit needs a sha" >&2; exit 2; } ;;
    --layout) LAYOUT_ONLY=1; shift ;;
    *) sed -n '2,12p' "$SEZI_UPDATE_COPY" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done
case "$TO" in ''|[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo "--to takes a build stamp (yyyyMMddHHmm), not '$TO'" >&2; exit 2 ;; esac
[ -z "$TO" ] || [ -z "$COMMIT" ] || { echo "--to and --commit name the same thing; give one" >&2; exit 2; }

[ "$(id -u)" = 0 ] || { echo "run as root (sudo): it stops and starts $UNIT" >&2; exit 1; }
as_user() { sudo -u "$RUN_AS" -H "$@"; }
USER_HOME=$(getent passwd "$RUN_AS" | cut -d: -f6)
[ -n "$USER_HOME" ] || { echo "no user '$RUN_AS' (SEZI_USER)" >&2; exit 1; }
WORKERD_LINK="$USER_HOME/.local/sezi-workerd/current"
git_() { as_user git -C "$SRV" "$@"; }

FROM_BUILD=""
result() { # result <ok> <code> [to]
  printf '{"to":%s,"from":%s,"ok":%s,"code":"%s","at":"%s"}\n' \
    "${3:-null}" "${FROM_BUILD:-null}" "$1" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESULT.tmp" &&
    mv "$RESULT.tmp" "$RESULT"
}
served() { curl -fsS --max-time 3 "http://127.0.0.1:$PORT/capabilities" | grep -o '"build":[0-9]*' | cut -d: -f2; }
healthy() {
  local h
  for _ in $(seq 1 30); do
    if h=$(curl -fsS --max-time 3 "http://127.0.0.1:$PORT/healthz" 2>/dev/null); then
      # A relay that answers but could not migrate is not the build that was asked for.
      case "$h" in *'"migrations":"failed'*) echo "migrations: $h"; return 1 ;; esac
      return 0
    fi
    sleep 2
  done
  return 1
}
build_of() { git_ show "$1:VERSION" 2>/dev/null | tr -dc 0-9; }

# ── 0. The layout: releases/ + current ──────────────────────────────────────────────────────
# An install from before it runs the clone's own workerd/; its build becomes the first release.
if [ ! -L "$SRV/current" ]; then
  B=$(build_of HEAD)
  [ -n "$B" ] || { echo "the clone's HEAD has no VERSION — not a sezi-server checkout?" >&2; exit 1; }
  echo "moving to the releases/ layout: $SRV/releases/$B, $SRV/current"
  as_user mkdir -p "$SRV/releases/$B.new" &&
    git_ archive HEAD | as_user tar -x -C "$SRV/releases/$B.new" &&
    git_ rev-parse HEAD | as_user tee "$SRV/releases/$B.new/.sezi-commit" >/dev/null &&
    as_user mv "$SRV/releases/$B.new" "$SRV/releases/$B" &&
    as_user ln -sfn "releases/$B" "$SRV/current" || { echo "could not export the running build" >&2; exit 1; }
  for p in /releases/ /current; do
    grep -qx "$p" "$SRV/.git/info/exclude" 2>/dev/null || echo "$p" | as_user tee -a "$SRV/.git/info/exclude" >/dev/null
  done
  if [ -f "$UNIT_FILE" ] && ! grep -q "$SRV/current/workerd/" "$UNIT_FILE"; then
    cp -p "$UNIT_FILE" "$UNIT_FILE.pre-releases"
    sed -i -e "s#$SRV/workerd/#$SRV/current/workerd/#g" -e "s#^WorkingDirectory=$SRV\$#WorkingDirectory=$SRV/current#" "$UNIT_FILE"
    if ! grep -q "$SRV/current/workerd/config.capnp" "$UNIT_FILE"; then
      cp -p "$UNIT_FILE.pre-releases" "$UNIT_FILE"
      echo "$UNIT_FILE does not run $SRV/workerd/config.capnp, so it was left alone. Point its" >&2
      echo "ExecStart at $SRV/current/workerd/config.capnp yourself, then run this again." >&2
      exit 1
    fi
    systemctl daemon-reload
    echo "  $UNIT_FILE now runs $SRV/current/ (the old unit: $UNIT_FILE.pre-releases);"
    echo "  the relay keeps running and moves there at its next restart"
  fi
  if [ -n "$LAYOUT_ONLY" ]; then result true layout "$B"; exit 0; fi
elif [ -n "$LAYOUT_ONLY" ]; then
  echo "already on the releases/ layout ($(readlink "$SRV/current"))"; exit 0
fi

OLD_REL=$(readlink "$SRV/current")
FROM_BUILD=${OLD_REL#releases/}
OLD_WORKERD=$(readlink "$WORKERD_LINK" || true)
echo "running: build $FROM_BUILD (serving $(served || echo '?'))"

# ── 1. Prepare, while the relay runs ────────────────────────────────────────────────────────
if ! git_ fetch -q origin; then
  echo "fetch failed — nothing was stopped or changed"; result false fetch-failed; exit 1
fi
BRANCH=$(git_ rev-parse --abbrev-ref HEAD)
[ "$BRANCH" != HEAD ] || BRANCH=main
UPSTREAM=origin/$BRANCH
if [ -n "$COMMIT" ]; then
  C=$(git_ rev-parse -q --verify "$COMMIT^{commit}") && git_ merge-base --is-ancestor "$C" "$UPSTREAM" || {
    echo "$COMMIT is not a commit of $UPSTREAM — refused, nothing changed"; result false not-published; exit 1; }
elif [ -n "$TO" ]; then
  C=""
  for c in $(git_ log --format=%H "$UPSTREAM" -- VERSION); do
    if [ "$(build_of "$c")" = "$TO" ]; then C=$c; break; fi
  done
  [ -n "$C" ] || { echo "no commit of $UPSTREAM carries build $TO — nothing changed"; result false no-such-build "$TO"; exit 1; }
else
  C=$(git_ rev-parse "$UPSTREAM")
fi
B=$(build_of "$C")
[ -n "$B" ] || { echo "$C has no VERSION — refused"; result false no-such-build; exit 1; }
[ -f "$SRV/releases/$B/workerd/config.capnp" ] || git_ cat-file -e "$C:workerd/config.capnp" 2>/dev/null || {
  echo "build $B predates the bare-workerd relay — refused"; result false too-old "$B"; exit 1; }
if [ "releases/$B" = "$OLD_REL" ]; then
  echo "already on build $B"
  git_ merge -q --ff-only "$UPSTREAM" 2>/dev/null || true
  result true already "$B"; exit 0
fi
echo "target: build $B (commit $C)"

REL="$SRV/releases/$B"
if [ ! -d "$REL" ] || [ "$(cat "$REL/.sezi-commit" 2>/dev/null)" != "$C" ]; then
  as_user rm -rf "$REL.new"
  as_user mkdir -p "$REL.new" &&
    git_ archive "$C" | as_user tar -x -C "$REL.new" &&
    echo "$C" | as_user tee "$REL.new/.sezi-commit" >/dev/null || {
      as_user rm -rf "$REL.new"; echo "export of $C failed — nothing was stopped"; result false export-failed "$B"; exit 1; }
  as_user rm -rf "$REL" && as_user mv "$REL.new" "$REL"
fi
# The workerd its lock names, checked against the lock's sha512 (deploy/fetch-workerd.sh; a no-op
# when that version is already there). It moves the `current` workerd link; the running relay
# keeps the binary it started with.
if ! as_user sh "$REL/deploy/fetch-workerd.sh" >/dev/null; then
  echo "fetch-workerd failed — the relay was never stopped"
  [ -n "$OLD_WORKERD" ] && as_user ln -sfn "$OLD_WORKERD" "$WORKERD_LINK"
  result false workerd-fetch-failed "$B"; exit 1
fi

# The installed unit is a copy the owner may have adapted, so it is never overwritten here; a
# difference from this build's is only said.
if [ -f "$UNIT_FILE" ] && ! cmp -s "$REL/deploy/sezi-relay.service" "$UNIT_FILE"; then
  echo "note: $UNIT_FILE differs from deploy/sezi-relay.service (compare them; see deploy/README.md)"
fi

# ── 2. Stop, back up, switch, start — the only downtime ─────────────────────────────────────
# The backup reads the state directory, so nothing may write it meanwhile: the relay is stopped
# (an explicit stop is never undone by `Restart=always`) and started only after the tar is done.
switch_back() {
  as_user ln -sfn "$OLD_REL" "$SRV/current"
  [ -n "$OLD_WORKERD" ] && as_user ln -sfn "$OLD_WORKERD" "$WORKERD_LINK"
}
systemctl stop "$UNIT"
if ! tar -C "$DATA" -cf "$BK" state; then
  echo "backup failed — starting the relay on another build without one is refused; staying on $FROM_BUILD"
  rm -f "$BK"; switch_back; systemctl start "$UNIT"
  result false backup-failed "$B"; exit 1
fi
as_user ln -sfn "releases/$B" "$SRV/current"
systemctl start "$UNIT"
echo "state backup: $BK ($(du -h "$BK" | cut -f1))"

# ── 3. Check: healthy AND serving the asked build, or roll back ─────────────────────────────
prune() {
  # Releases: the newest $KEEP by build, never the running one nor the one it came from.
  local keep n=0 r
  keep=$(ls -1 "$SRV/releases" | grep -E '^[0-9]{12}$' | sort -rn | head -n "$KEEP")
  for r in $(ls -1 "$SRV/releases"); do
    case " $(echo $keep) $B $FROM_BUILD " in *" $r "*) continue ;; esac
    as_user rm -rf "${SRV:?}/releases/$r" && echo "  pruned release $r"
  done
  # State backups: the newest $KEEP.
  for r in $(ls -1t "$DATA"/backup-pre-update-*.tar 2>/dev/null); do
    n=$((n + 1)); [ $n -le "$KEEP" ] || { rm -f "$r" && echo "  pruned backup $(basename "$r")"; }
  done
  # workerd versions no kept release names.
  local wbase=$USER_HOME/.local/sezi-workerd wanted v
  wanted=$(cat "$SRV"/releases/*/workerd/WORKERD.lock 2>/dev/null | awk '$1 == "version" { print $2 }' | sort -u)
  for v in $(ls -1 "$wbase" 2>/dev/null); do
    [ "$v" = current ] && continue
    echo "$wanted" | grep -qx "$v" || { as_user rm -rf "${wbase:?}/$v" && echo "  pruned workerd $v"; }
  done
}

if healthy && [ "$(served)" = "$B" ]; then
  echo "OK: healthy on build $B"
  journalctl -u "$UNIT" --since "-2min" --no-pager | grep -iE "migrat|provision|error" | tail -8
  prune
  # Keep the clone's own scripts (this one, fetch-workerd.sh, the unit) at the newest published.
  git_ merge -q --ff-only "$UPSTREAM" 2>/dev/null || echo "note: the clone could not fast-forward to $UPSTREAM (local changes?)"
  result true ok "$B"
  exit 0
fi

echo "FAIL: not healthy on build $B — rolling back to $FROM_BUILD"
systemctl stop "$UNIT"
switch_back
rm -rf "$ST" && tar -C "$DATA" -xf "$BK"
systemctl daemon-reload
systemctl start "$UNIT"
if healthy; then
  echo "rolled back, healthy on build $FROM_BUILD"; result false unhealthy-rolled-back "$B"
else
  echo "ROLLBACK ALSO UNHEALTHY — journalctl -u $UNIT"; result false rollback-unhealthy "$B"
fi
journalctl -u "$UNIT" -n 30 --no-pager
exit 1
