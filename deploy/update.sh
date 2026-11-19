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
# channels/stable/ after the fetch — and verified with openssl against ROOT'S OWN copy of the
# release keys ($SEZI_UPDATER_DIR/release-keys, see below). The highest `seq` that verifies wins;
# one lower than this box already accepted ($SEZI_UPDATER_STATE/release-seq) is a replay and is
# refused. Only a build the manifest names is installed: its newest (`server.build`, at exactly
# `server.template_commit`), or one of `kept.server` ("go back"). The newest build's workerd/ tree is
# checked against the signed `server.workerd.bundle`. A run without --to never goes BACK to the
# channel's newest from a newer build. Needs openssl 3 and jq. Where no channel is published yet a
# run by hand still moves by the template's history alone, and says so; a --signed run refuses
# (`no-manifest`).
#
# WHAT ROOT RUNS AND TRUSTS. The clone, its releases/ and the state directory belong to $SEZI_USER,
# the account the relay runs as — so a relay someone took could change anything in them. Root
# therefore runs this script, the poll script and the release keys only from a root-owned copy,
# $SEZI_UPDATER_DIR (/usr/local/lib/sezi-updater, made by install-updater.sh), and keeps its own
# files — the lock, the accepted seq, the result, the state backups — in $SEZI_UPDATER_STATE
# (/var/lib/sezi-updater, root only). Every git command runs as $SEZI_USER, and so does every tar
# that reads or writes the state; root holds only the bytes. The root copy is refreshed only from
# the commit a manifest that verified names as the newest (refresh_updater below), so a new key or
# a new update.sh arrives only through a release a key root already trusts signed. Without the root
# copy (a run by hand on a box with no update timers) the keys of the build that runs are used, and
# that is said: they are in a tree $SEZI_USER can write.
#
# LAYOUT. The clone stays where it was and only fetches; every build runs from its own exported tree:
#
#   /opt/sezi-server/                      the git clone: fetch, deploy/ (this script), .dev.vars
#   /opt/sezi-server/releases/<build>/     one tree per build (git archive of its commit), never edited
#   /opt/sezi-server/current -> releases/<build>     what the unit runs (ExecStart reads
#                                                    current/workerd/config.capnp)
#   /usr/local/lib/sezi-updater/           root's copy: update.sh, sezi-update-poll.sh,
#                                          release-keys/, .sezi-commit (the commit it came from)
#   /var/lib/sezi-updater/                 root only: update.lock, release-seq, update-result.json,
#                                          backup-pre-update-*.tar, failed-state-*.tar
#
# The newest SEZI_KEEP (3) releases and state backups are kept, older ones pruned, and with them the
# workerd versions no kept release names. The state a rolled-back build left (failed-state-*) is
# never pruned. Going back to a kept build moves `current` and restarts:
# its data stays as it is — the relay's migrations are expand-only, so the previous build runs on
# the newer schema (AGENTS.md, "Relay migrations are expand-only"). An install from before this
# layout is moved on its first run (its unit's paths are rewritten once, the old unit kept beside
# it as <unit>.service.pre-releases) — and it says so.
#
# The relay is stopped only for the backup and the restart — about two seconds. Everything that can
# take long (the fetch, the export, a new workerd download) happens first, while the relay runs.
# Clients ride the gap: they reconnect within a second and resend what was not acked.
#
# The result is also written to $SEZI_UPDATER_STATE/update-result.json ({to, from, ok, code, at});
# the update timer (sezi-update-poll.sh) reports it to the relay, which tells the owner's app.
# One run at a time ($SEZI_UPDATER_STATE/update.lock): a second exits 3 and writes no result.
#
# Environment (optional): SEZI_DIR (/opt/sezi-server), SEZI_DATA (/var/lib/sezi), SEZI_UNIT
# (sezi-relay), SEZI_PORT (8788), SEZI_USER (sezi — the user the relay runs as and owns the clone),
# SEZI_KEEP (3), SEZI_UNIT_DIR (/etc/systemd/system), SEZI_RELEASE_HOSTS (the release hosts, space
# separated — the app's own list by default), SEZI_REQUIRE_SIGNED (1 = as --signed),
# SEZI_UPDATER_DIR (/usr/local/lib/sezi-updater), SEZI_UPDATER_STATE (/var/lib/sezi-updater).
set -uo pipefail

# Run from a copy: a fetch, the final fast-forward or a refresh of the root copy may replace this
# file, and bash reads a script while it runs it.
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
UNIT_DIR="${SEZI_UNIT_DIR:-/etc/systemd/system}"
UNIT_FILE="$UNIT_DIR/$UNIT.service"
UPD="${SEZI_UPDATER_DIR:-/usr/local/lib/sezi-updater}"
UST="${SEZI_UPDATER_STATE:-/var/lib/sezi-updater}"
ST="$DATA/state"
TS=$(date +%Y%m%d-%H%M%S)
BK="$UST/backup-pre-update-$TS.tar"
RESULT="$UST/update-result.json"

HOSTS="${SEZI_RELEASE_HOSTS-https://releases.revisetouch.work https://releases.revisetouch.com}"
SEQ_FILE="$UST/release-seq"
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
# Root's own directory: nothing in it is a path $RUN_AS could have put a link at.
mkdir -p "$UST" && chmod 0700 "$UST" || { echo "cannot make $UST" >&2; exit 1; }
exec 9>"$UST/update.lock"
flock -n 9 || { echo "another update is running ($UST/update.lock)" >&2; exit 3; }
as_user() { sudo -u "$RUN_AS" -H "$@"; }
USER_HOME=$(getent passwd "$RUN_AS" | cut -d: -f6)
[ -n "$USER_HOME" ] || { echo "no user '$RUN_AS' (SEZI_USER)" >&2; exit 1; }
WORKERD_LINK="$USER_HOME/.local/sezi-workerd/current"
git_() { as_user git -C "$SRV" "$@"; }
# The seq a box from before $UST accepted, taken over once (digits only; read as $RUN_AS).
if [ ! -s "$SEQ_FILE" ]; then
  old_seq=$(as_user cat "$DATA/release-seq" 2>/dev/null | tr -dc 0-9)
  [ -z "$old_seq" ] || echo "$old_seq" > "$SEQ_FILE"
fi
# The release keys root believes: its own copy, else (no update timers installed) the running
# build's — found in find_manifest, after the layout move — which is said.
KEYS=""; ls "$UPD/release-keys"/*.pem >/dev/null 2>&1 && KEYS=$UPD/release-keys

FROM_BUILD=""
result() { # result <ok> <code> [to]
  printf '{"to":%s,"from":%s,"ok":%s,"code":"%s","at":"%s"}\n' \
    "${3:-null}" "${FROM_BUILD:-null}" "$1" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESULT.tmp" &&
    mv "$RESULT.tmp" "$RESULT" || return 1
  # A copy where a poll script from before the root copy looks for it (it only reports it to the
  # relay), written as $RUN_AS: root never writes a path in a directory that user owns.
  as_user sh -c 'cat > "$1.tmp" && mv "$1.tmp" "$1"' sh "$DATA/update-result.json" < "$RESULT" 2>/dev/null || true
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
  local keys n=0 answered="" rollback="" h seq have
  if [ -z "$KEYS" ]; then
    KEYS=$SRV/current/deploy/release-keys; [ -d "$KEYS" ] || KEYS=$SRV/deploy/release-keys
    echo "WARNING: no root copy of the updater ($UPD), so the release keys are read from $KEYS,"
    echo "  which $RUN_AS can write. Install the update timers (deploy/install-updater.sh) to fix that."
  fi
  keys=$KEYS
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

# ── The updater's own root copy ─────────────────────────────────────────────────────────────
# Root runs the updater from $UPD and believes the keys in $UPD/release-keys, never anything in the
# clone (see the header). This keeps that copy current, and it is the only way anything gets in:
#
#   root's keys verify the manifest → the manifest names server.template_commit → the files are read
#   out of THAT commit in a repository root makes for the purpose.
#
# $RUN_AS hands the objects over (its git, and so its answer, may be anything), but index-pack names
# every object by the hash of its own bytes, and root then resolves commit → tree → file by those
# names: what lands in $UPD is what the signed commit holds, or nothing. Never a copy of a file from
# the clone or a release tree. A new key (or a new update.sh) therefore arrives only in a commit a key
# root already trusted signed. Run only when $UPD or the update timers exist; it also moves timers
# from before the root copy (they ran the clone's poll script) onto it.
refresh_updater() { # refresh_updater <commit the verified manifest names as the newest>
  local c=$1 g S f mode type sha name n=0 u changed=""
  [ -d "$UPD" ] || [ -f "$UNIT_DIR/sezi-update.service" ] || return 0
  printf '%s' "$c" | grep -qxE '[0-9a-f]{40}|[0-9a-f]{64}' || { echo "note: the manifest's commit '$c' is no full id; the updater's root copy is left as it is"; return 1; }
  if [ "$(cat "$UPD/.sezi-commit" 2>/dev/null)" != "$c" ] || [ ! -f "$UPD/sezi-update-poll.sh" ]; then
    g=$(mktemp -d) || return 1
    rgit() { GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$g/r" "$@"; }
    if ! GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        git init -q --bare --object-format="$([ ${#c} = 64 ] && echo sha256 || echo sha1)" "$g/r" ||
      ! { echo "$c"
          git_ rev-parse "$c^{tree}" "$c:deploy" "$c:deploy/release-keys"
          git_ ls-tree "$c" deploy/update.sh deploy/sezi-update-poll.sh | awk '{ print $3 }'
          git_ ls-tree "$c:deploy/release-keys" | awk '{ print $3 }'
        } 2>/dev/null | git_ pack-objects -q --stdout | rgit index-pack --stdin >/dev/null 2>&1; then
      rm -rf "$g"; echo "note: the objects of $c could not be read; the updater's root copy is left as it is"; return 1
    fi
    install -d -m 0755 "$UPD" || { rm -rf "$g"; return 1; }
    S=$UPD/.staging; rm -rf "$S"; install -d -m 0755 "$S" "$S/release-keys"
    for f in update.sh sezi-update-poll.sh; do
      case "$(rgit ls-tree "$c" -- "deploy/$f")" in 100644\ blob\ *|100755\ blob\ *) ;; *) n=-1 ;; esac
      rgit cat-file blob "$c:deploy/$f" > "$S/$f" 2>/dev/null && chmod 0755 "$S/$f" && bash -n "$S/$f" 2>/dev/null || n=-1
    done
    while [ "$n" -ge 0 ] && read -r mode type sha name; do
      case "$mode $type $name" in "100644 blob "*.pem) ;; *) continue ;; esac
      case "$name" in *[!A-Za-z0-9._-]*) continue ;; esac
      rgit cat-file blob "$sha" > "$S/release-keys/$name" && chmod 0644 "$S/release-keys/$name" && n=$((n + 1)) || n=-1
    done < <(rgit ls-tree "$c:deploy/release-keys" 2>/dev/null)
    rm -rf "$g"
    if [ "$n" -lt 1 ]; then
      rm -rf "$S"; echo "note: the updater of $c (two scripts, a key at least) could not be read out of it; the root copy is left as it is"; return 1
    fi
    chown -R root:root "$S"
    mv -f "$S/update.sh" "$UPD/update.sh" && mv -f "$S/sezi-update-poll.sh" "$UPD/sezi-update-poll.sh" &&
      rm -rf "$UPD/.old-keys" && { [ ! -d "$UPD/release-keys" ] || mv "$UPD/release-keys" "$UPD/.old-keys"; } &&
      mv "$S/release-keys" "$UPD/release-keys" && rm -rf "$UPD/.old-keys" "$S" &&
      echo "$c" > "$UPD/.sezi-commit" || { echo "note: the updater's root copy could not be replaced ($UPD)"; return 1; }
    echo "the updater's root copy ($UPD) is now that of commit $c ($n key(s))"
  fi
  # Timers from before the root copy ran the clone's poll script: point them at the root copy.
  for u in sezi-update.service sezi-update-nightly.service; do
    f=$UNIT_DIR/$u
    [ -f "$f" ] && grep -q "^ExecStart=/bin/bash $SRV/deploy/sezi-update-poll.sh" "$f" || continue
    sed -i -e "s#^ExecStart=/bin/bash $SRV/deploy/sezi-update-poll.sh#ExecStart=/bin/bash $UPD/sezi-update-poll.sh#" \
      -e "/^\[Service\]\$/a Environment=SEZI_UPDATER_DIR=$UPD SEZI_UPDATER_STATE=$UST" "$f" && changed=1
  done
  [ -z "$changed" ] || { systemctl daemon-reload; echo "the update timers now run $UPD/sezi-update-poll.sh"; }
  return 0
}
# After a run that ended well with a verified manifest: the root copy follows the channel's newest.
refresh_from_channel() { [ -z "$M" ] || refresh_updater "$LATEST_C" || true; }

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
# The link is $RUN_AS's: what it says goes into root's result and paths only as a build stamp.
case "$FROM_BUILD" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo "$SRV/current points at '$OLD_REL', not releases/<build> — refused" >&2; exit 1 ;; esac
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
    2) echo "a release manifest was found but none verifies against $KEYS — refused"
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
    C=$(as_user cat "$SRV/releases/$TO/.sezi-commit" 2>/dev/null | tr -dc 0-9a-f) || C=""
    [ -n "$C" ] || C=$(by_history "$TO") || {
      echo "no commit of $UPSTREAM carries build $TO — nothing changed"; result false no-such-build "$TO"; exit 1; }
    WANT=$TO
  else
    C=$LATEST_C; WANT=$LATEST
    if [ -z "$TO" ] && [ -n "$ONLY_SECURITY" ] && [ -z "$(mf .server.security.level)" ]; then
      echo "build $LATEST is not a security release — nothing to do"; result true not-security "$LATEST"
      refresh_from_channel; exit 0
    fi
    if [ -z "$TO" ] && [ "$LATEST" -lt "$FROM_BUILD" ]; then
      echo "build $FROM_BUILD runs, newer than the channel's $LATEST — nothing to do (--to goes back)"
      result true newer-running "$LATEST"; refresh_from_channel; exit 0
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
  result true already "$B"; refresh_from_channel; exit 0
fi
echo "target: build $B (commit $C)"

REL="$SRV/releases/$B"
if [ ! -d "$REL" ] || [ "$(as_user cat "$REL/.sezi-commit" 2>/dev/null)" != "$C" ]; then
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
# tar reads the state as $RUN_AS (it is that user's tree, links and all); root only keeps the bytes,
# in its own directory.
if ! as_user tar -C "$DATA" -cf - state > "$BK"; then
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
  for r in $(ls -1t "$UST"/backup-pre-update-*.tar 2>/dev/null); do
    n=$((n + 1)); [ $n -le "$KEEP" ] || { rm -f "$r" && echo "  pruned backup $(basename "$r")"; }
  done
  # workerd versions no kept release names.
  local wbase=$USER_HOME/.local/sezi-workerd wanted v
  wanted=$(as_user sh -c 'cat "$1"/releases/*/workerd/WORKERD.lock' sh "$SRV" 2>/dev/null | awk '$1 == "version" { print $2 }' | sort -u)
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
  refresh_from_channel
  exit 0
fi

echo "FAIL: not healthy on build $B — rolling back to $FROM_BUILD"
systemctl stop "$UNIT"
switch_back
# The backup is the state from before the update, so whatever the new build accepted meanwhile (a
# message, a sign-up) is not in it. That state is kept, not deleted: as a tar beside the backups, or
# — when it cannot be written — as the directory itself, moved aside. Never pruned.
FAILED="$UST/failed-state-$B-$TS.tar"
if as_user tar -C "$DATA" -cf - state > "$FAILED"; then
  echo "the state build $B left is kept: $FAILED (restoring the backup from before it drops anything it accepted)"
  rm -rf "$ST"
else
  rm -f "$FAILED"
  as_user mv "$ST" "$DATA/state-failed-$B-$TS" &&
    echo "the state build $B left is kept: $DATA/state-failed-$B-$TS"
fi
if [ -e "$ST" ]; then
  echo "WARNING: the state build $B left could be neither saved nor moved aside, so the backup was NOT"
  echo "  restored (the relay starts on that state); the backup from before the update is $BK"
else
  as_user tar -C "$DATA" -xf - < "$BK"
fi
systemctl daemon-reload
systemctl start "$UNIT"
if healthy; then
  echo "rolled back, healthy on build $FROM_BUILD"; result false unhealthy-rolled-back "$B"
else
  echo "ROLLBACK ALSO UNHEALTHY — journalctl -u $UNIT"; result false rollback-unhealthy "$B"
fi
journalctl -u "$UNIT" -n 30 --no-pager
exit 1
