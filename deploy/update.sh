#!/usr/bin/env bash
# Update a hand-installed relay (deploy/README.md layout) — or move it to another build it can go
# back to — with a backup of its data and an automatic rollback if it does not come back healthy.
#
#   sudo bash /opt/sezi-server/deploy/update.sh                 the newest build of the signed channel
#   sudo bash /opt/sezi-server/deploy/update.sh --to <build>    that build (the yyyyMMddHHmm in its
#                                                               VERSION): newer, or a kept older one
#   sudo bash /opt/sezi-server/deploy/update.sh --commit <sha>  exactly that template commit (the one
#                                                               a signed release names)
#   sudo bash /opt/sezi-server/deploy/update.sh --layout        only move an older install to the
#                                                               releases/ layout below
#   --signed          refuse unless a signed manifest names the build (the update timer always says it)
#   --only-security   the newest build only when its release is a security fix (the nightly switch)
#
# THE SIGNED CHANNEL (docs/SERVER_UPDATE_PLAN.md §1, §4.1). Before anything moves, the release
# manifest is fetched — from each release host (SEZI_RELEASE_HOSTS) and from the template's own
# channels/stable/ after the fetch — and verified with openssl against the key files of the build
# that RUNS (current/deploy/release-keys/: a new key arrives only through a release an old key
# signed). The highest `seq` that verifies wins; one lower than this box already accepted
# ($SEZI_DATA/release-seq) is a replay and is refused. Only a build the manifest names is installed:
# its newest (`server.build`, at exactly `server.template_commit`), or one of `kept.server` ("go
# back"). The newest build's workerd/ tree is checked against the signed `server.workerd.bundle`.
# A run without --to never goes BACK to the channel's newest from a newer build. Needs openssl 3 and
# jq. Where no channel is published yet a run by hand still moves by the template's history alone,
# and says so; a --signed run refuses (`no-manifest`). After a signed update the clone moves only to
# the signed commit, so root never runs a script no release named.
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
# The result is also written to $SEZI_DATA/update-result.json ({to, from, ok, code, at}); the
# update timer (deploy/sezi-update-poll.sh) reports it to the relay, which tells the owner's app.
# One run at a time ($SEZI_DATA/update.lock): a second exits 3 and writes no result.
#
# Environment (optional): SEZI_DIR (/opt/sezi-server), SEZI_DATA (/var/lib/sezi), SEZI_UNIT
# (sezi-relay), SEZI_PORT (8788), SEZI_USER (sezi — the user the relay runs as and owns the clone),
# SEZI_KEEP (3), SEZI_UNIT_DIR (/etc/systemd/system), SEZI_RELEASE_HOSTS (the release hosts, space
# separated — the app's own list by default), SEZI_REQUIRE_SIGNED (1 = as --signed).
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

HOSTS="${SEZI_RELEASE_HOSTS-https://releases.revisetouch.work https://releases.revisetouch.com}"
SEQ_FILE="$DATA/release-seq"
CHANNEL=stable

TO=""; COMMIT=""; LAYOUT_ONLY=""; ONLY_SECURITY=""
SIGNED=""; [ "${SEZI_REQUIRE_SIGNED:-}" = 1 ] && SIGNED=1
while [ $# -gt 0 ]; do
  case "$1" in
    --to) TO=${2:-}; shift 2 || { echo "--to needs a build" >&2; exit 2; } ;;
    --commit) COMMIT=${2:-}; shift 2 || { echo "--commit needs a sha" >&2; exit 2; } ;;
    --layout) LAYOUT_ONLY=1; shift ;;
    --signed) SIGNED=1; shift ;;
    --only-security) ONLY_SECURITY=1; SIGNED=1; shift ;; # "is it a security fix" only a manifest says
    *) sed -n '2,13p' "$SEZI_UPDATE_COPY" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done
case "$TO" in ''|[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo "--to takes a build stamp (yyyyMMddHHmm), not '$TO'" >&2; exit 2 ;; esac
[ -z "$TO" ] || [ -z "$COMMIT" ] || { echo "--to and --commit name the same thing; give one" >&2; exit 2; }

[ "$(id -u)" = 0 ] || { echo "run as root (sudo): it stops and starts $UNIT" >&2; exit 1; }
mkdir -p "$DATA"
exec 9>"$DATA/update.lock"
flock -n 9 || { echo "another update is running ($DATA/update.lock)" >&2; exit 3; }
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

# ── The signed channel ──────────────────────────────────────────────────────────────────────
# verify <manifest> <sig> <keydir>: the signature line (`<key id> <base64>`) over the manifest's
# exact bytes with the pinned key of that id, then the fields trust rests on. Prints its seq.
verify() {
  local m=$1 s=$2 keys=$3 id b64 tmp
  read -r id b64 _ < "$s" || return 1
  case "$id" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
  [ -f "$keys/$id.pem" ] && [ -n "$b64" ] || return 1
  tmp=$(mktemp) || return 1
  if ! printf '%s' "$b64" | base64 -d > "$tmp" 2>/dev/null ||
    ! openssl pkeyutl -verify -pubin -inkey "$keys/$id.pem" -rawin -in "$m" -sigfile "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"; return 1
  fi
  rm -f "$tmp"
  jq -er --arg id "$id" --arg ch "$CHANNEL" \
    'select(.schema == 1 and .key_id == $id and .channel == $ch and (.seq | type) == "number") | .seq' "$m" 2>/dev/null
}
# The manifest: every source tried, the highest seq that verifies kept in $MDIR/manifest.json.
# Sets M (its path), M_SEQ, M_FROM (the host it came from, empty for the template's mirror).
# Returns 1 = nothing published anywhere, 2 = something answered and nothing verified, 3 = only
# replays of an older seq.
find_manifest() {
  local keys=$SRV/current/deploy/release-keys n=0 answered="" rollback="" h seq have
  [ -d "$keys" ] || keys=$SRV/deploy/release-keys
  have=$(cat "$SEQ_FILE" 2>/dev/null | tr -dc 0-9); have=${have:-0}
  M=""; M_SEQ=0; M_FROM=""
  try_one() { # try_one <manifest> <sig> <from>
    answered=1
    if ! seq=$(verify "$1" "$2" "$keys"); then echo "  $3: does not verify — skipped"; return; fi
    if [ "$seq" -lt "$have" ]; then echo "  $3: seq $seq is older than $have — skipped"; rollback=1; return; fi
    if [ "$seq" -gt "$M_SEQ" ] || [ -z "$M" ]; then
      cp -f "$1" "$MDIR/manifest.json" && M=$MDIR/manifest.json M_SEQ=$seq M_FROM=$3
      [ "$3" = mirror ] && M_FROM=""
    fi
  }
  for h in $HOSTS; do
    n=$((n + 1))
    if curl -fsS --connect-timeout 5 --max-time 15 -o "$MDIR/h$n.json" "$h/channels/$CHANNEL/manifest.json?t=$TS" 2>/dev/null &&
      curl -fsS --connect-timeout 5 --max-time 15 -o "$MDIR/h$n.sig" "$h/channels/$CHANNEL/manifest.json.sig?t=$TS" 2>/dev/null; then
      try_one "$MDIR/h$n.json" "$MDIR/h$n.sig" "$h"
    fi
  done
  if git_ show "$UPSTREAM:channels/$CHANNEL/manifest.json" > "$MDIR/mirror.json" 2>/dev/null &&
    git_ show "$UPSTREAM:channels/$CHANNEL/manifest.json.sig" > "$MDIR/mirror.sig" 2>/dev/null; then
    try_one "$MDIR/mirror.json" "$MDIR/mirror.sig" mirror
  fi
  [ -n "$M" ] && return 0
  [ -n "$rollback" ] && return 3
  [ -n "$answered" ] && return 2
  return 1
}
mf() { jq -r "$1 // empty" "$M"; }
# The newest build's workerd/ against the signed bundle: the same `git archive | gzip -n` the
# release script made gives the same sha256. When it does not (another gzip), the bundle itself is
# fetched from the host the manifest came from and its tree compared; from the mirror alone the
# commit pin stands, and that is said.
bundle_ok() { # bundle_ok <commit> <release dir>
  local want url got t
  want=$(mf .server.workerd.bundle.sha256); url=$(mf .server.workerd.bundle.url)
  [ -n "$want" ] || { echo "  note: the release names no workerd bundle"; return 0; }
  got=$(git_ archive "$1" workerd | gzip -n | sha256sum | cut -d' ' -f1)
  [ "$got" = "$want" ] && return 0
  if [ -z "$M_FROM" ] || [ -z "$url" ]; then
    echo "  note: workerd/ could not be compared with the signed bundle here; the signed commit pins it"
    return 0
  fi
  t=$(mktemp -d) || return 1
  if curl -fsS --connect-timeout 5 --max-time 120 -o "$t/b.tgz" "$M_FROM$url" 2>/dev/null &&
    [ "$(sha256sum "$t/b.tgz" | cut -d' ' -f1)" = "$want" ] &&
    mkdir "$t/x" && tar -xzf "$t/b.tgz" -C "$t/x" && diff -r "$t/x/workerd" "$2/workerd" >/dev/null; then
    rm -rf "$t"; return 0
  fi
  rm -rf "$t"; return 1
}

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
by_history() { # the commit of $UPSTREAM that carries build $1
  local c
  for c in $(git_ log --format=%H "$UPSTREAM" -- VERSION); do
    if [ "$(build_of "$c")" = "$1" ]; then echo "$c"; return 0; fi
  done
  return 1
}

# 1a. The signed channel: which builds may be installed, and at which commit.
M=""; LATEST=""
if command -v jq >/dev/null && command -v openssl >/dev/null; then
  MDIR=$(mktemp -d) || exit 1
  trap 'rm -f "$SEZI_UPDATE_COPY"; rm -rf "$MDIR"' EXIT
  find_manifest; found=$?
  case $found in
    0) echo "signed channel: $CHANNEL seq $M_SEQ (${M_FROM:-the template mirror})" ;;
    2) echo "a release manifest was found but none verifies against $SRV/current/deploy/release-keys — refused"
       result false bad-signature "${TO:-null}"; exit 1 ;;
    3) echo "only an older release manifest than this box already accepted was found — refused"
       result false seq-rollback "${TO:-null}"; exit 1 ;;
  esac
elif [ -n "$SIGNED" ]; then
  echo "openssl and jq are needed to check the signed channel — refused"; result false verify-tools-missing; exit 1
else
  echo "WARNING: no openssl/jq here, so the signed channel is not checked (apt install jq)"
fi
if [ -n "$M" ]; then
  LATEST=$(mf .server.build); LATEST_C=$(mf .server.template_commit)
  FLOOR=$(mf .server.schema_floor_build); FLOOR=${FLOOR:-0}
  case "$LATEST" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) echo "the signed manifest names no server build — refused"; result false not-in-channel "${TO:-null}"; exit 1 ;; esac
  if [ -n "$COMMIT" ]; then
    C=$(git_ rev-parse -q --verify "$COMMIT^{commit}")
    [ -n "$C" ] && [ "$C" = "$(git_ rev-parse -q --verify "$LATEST_C^{commit}")" ] || {
      echo "$COMMIT is not the commit the signed release names — refused"; result false not-in-channel; exit 1; }
    WANT=$LATEST
  elif [ -n "$TO" ] && [ "$TO" != "$LATEST" ]; then
    mf '.kept.server[]?' | grep -qx "$TO" && [ "$TO" -ge "$FLOOR" ] || {
      echo "build $TO is not one the signed channel offers (newest $LATEST, kept: $(mf '.kept.server[]?' | tr '\n' ' '))"
      result false not-in-channel "$TO"; exit 1; }
    # A kept build: the tree this box already ran (verified when it was installed), or the
    # template's history.
    C=$(cat "$SRV/releases/$TO/.sezi-commit" 2>/dev/null) || C=""
    [ -n "$C" ] || C=$(by_history "$TO") || {
      echo "no commit of $UPSTREAM carries build $TO — nothing changed"; result false no-such-build "$TO"; exit 1; }
    WANT=$TO
  else
    C=$LATEST_C; WANT=$LATEST
    if [ -z "$TO" ] && [ -n "$ONLY_SECURITY" ] && [ -z "$(mf .server.security.level)" ]; then
      echo "build $LATEST is not a security release — nothing to do"; result true not-security "$LATEST"; exit 0
    fi
    if [ -z "$TO" ] && [ "$LATEST" -lt "$FROM_BUILD" ]; then
      echo "build $FROM_BUILD runs, newer than the channel's $LATEST — nothing to do (--to goes back)"
      result true newer-running "$LATEST"; exit 0
    fi
  fi
  { git_ cat-file -e "$C^{commit}" 2>/dev/null && git_ merge-base --is-ancestor "$C" "$UPSTREAM"; } || {
    echo "commit $C of build $WANT is not on $UPSTREAM — refused, nothing changed"; result false not-published "$WANT"; exit 1; }
  echo "$M_SEQ" > "$SEQ_FILE"
elif [ -n "$SIGNED" ]; then
  echo "no signed release channel answered — refused (a run by hand moves by the template's history)"
  result false no-manifest "${TO:-null}"; exit 1
else
  # No channel published yet: the template's history alone, as before step 6.
  echo "note: no signed release channel answered; moving by $UPSTREAM's history alone (GitHub + TLS)"
  if [ -n "$COMMIT" ]; then
    C=$(git_ rev-parse -q --verify "$COMMIT^{commit}") && git_ merge-base --is-ancestor "$C" "$UPSTREAM" || {
      echo "$COMMIT is not a commit of $UPSTREAM — refused, nothing changed"; result false not-published; exit 1; }
  elif [ -n "$TO" ]; then
    C=$(by_history "$TO") || { echo "no commit of $UPSTREAM carries build $TO — nothing changed"; result false no-such-build "$TO"; exit 1; }
  else
    C=$(git_ rev-parse "$UPSTREAM")
  fi
  WANT=""
fi
B=$(build_of "$C")
[ -n "$B" ] || { echo "$C has no VERSION — refused"; result false no-such-build; exit 1; }
[ -z "$WANT" ] || [ "$B" = "$WANT" ] || {
  echo "commit $C carries build $B, not the $WANT the signed release names — refused"; result false version-mismatch "$WANT"; exit 1; }
[ -f "$SRV/releases/$B/workerd/config.capnp" ] || git_ cat-file -e "$C:workerd/config.capnp" 2>/dev/null || {
  echo "build $B predates the bare-workerd relay — refused"; result false too-old "$B"; exit 1; }
# Where the clone's own scripts move after this run: to the signed commit (never past it — root runs
# them next time), or, with no channel, to the newest published.
CLONE_TO=$UPSTREAM; [ -z "$M" ] || CLONE_TO=$C
if [ "releases/$B" = "$OLD_REL" ]; then
  echo "already on build $B"
  git_ merge -q --ff-only "$CLONE_TO" 2>/dev/null || true
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
if [ -n "$M" ] && [ "$B" = "$LATEST" ] && ! bundle_ok "$C" "$REL"; then
  echo "build $B's workerd/ does not match the signed bundle — refused, the relay was never stopped"
  result false bundle-mismatch "$B"; exit 1
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
  git_ merge -q --ff-only "$CLONE_TO" 2>/dev/null || echo "note: the clone could not fast-forward to $CLONE_TO (local changes, or it is past it)"
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
