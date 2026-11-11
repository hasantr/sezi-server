#!/usr/bin/env bash
# The box's half of the owner's one-tap update (docs/SERVER_UPDATE_PLAN.md §4.2–4.3), run as root
# by sezi-update.timer every two minutes and by sezi-update-nightly.timer once a night
# (deploy/install-updater.sh installs both).
#
#   sezi-update-poll.sh             ask the relay whether its owner asked for a build; if so, run
#                                   deploy/update.sh --signed --to <build> and report how it ended
#   sezi-update-poll.sh --nightly   when the owner turned on automatic updates, run update.sh
#                                   --signed (--only-security for "security updates only") and
#                                   report it if anything was done
#
# The relay is asked on loopback, with the updater token from $SEZI_UPDATER_TOKEN_FILE
# (/etc/sezi/updater-token): `GET /internal/update-request`. Each ask is also how the relay knows
# this box's updater is alive (`/capabilities` `updater`), which is what makes the owner's app offer
# the button. Root takes nothing from the relay but a build stamp (twelve digits) and the switch
# (off/all/security); update.sh installs only a build the SIGNED release channel names, so a relay
# that was taken can at most ask for a build Hasan's key signed.
#
# Environment (optional): SEZI_DIR, SEZI_DATA, SEZI_PORT as update.sh; SEZI_UPDATER_TOKEN_FILE;
# SEZI_UPDATE_SH (the update script, default $SEZI_DIR/deploy/update.sh).
set -uo pipefail

SRV="${SEZI_DIR:-/opt/sezi-server}"
DATA="${SEZI_DATA:-/var/lib/sezi}"
PORT="${SEZI_PORT:-8788}"
TOKEN_FILE="${SEZI_UPDATER_TOKEN_FILE:-/etc/sezi/updater-token}"
UPDATE_SH="${SEZI_UPDATE_SH:-$SRV/deploy/update.sh}"
RESULT="$DATA/update-result.json"
BASE="http://127.0.0.1:$PORT"

NIGHTLY=""
case "${1:-}" in
  "") ;;
  --nightly) NIGHTLY=1 ;;
  *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

# No token: no updater was installed (or it was removed). Nothing to do, quietly.
TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE" 2>/dev/null) || exit 0
[ -n "$TOKEN" ] || exit 0

ask() {
  curl -fsS --max-time 10 -H "x-sezi-updater: $TOKEN" "$BASE/internal/update-request"
}
# report <json> — how a run ended, to the relay that answers after it (the new build or the
# restored one). A relay that does not answer at once (it is still starting) is asked again.
report() {
  local i
  for i in 1 2 3 4 5 6; do
    curl -fsS --max-time 10 -H "x-sezi-updater: $TOKEN" -H 'content-type: application/json' \
      --data-binary "$1" "$BASE/internal/update-result" >/dev/null 2>&1 && return 0
    [ "$i" = 6 ] || sleep 5
  done
  echo "the result could not be reported: $1" >&2
  return 1
}
# The result update.sh wrote, with `request_id` put in front; a run that wrote none (it refused its
# arguments, or another update held the lock) is reported as such.
result_json() { # result_json <request id or empty> <code when there is no result file>
  local head=""
  [ -z "$1" ] || head="\"request_id\":$1,"
  if [ -s "$RESULT" ]; then
    sed "s/^{/{$head/" "$RESULT"
  else
    printf '{%s"to":null,"from":null,"ok":false,"code":"%s"}\n' "$head" "$2"
  fi
}
# A busy lock is said before asking: a request is "picked" when it is handed out, so it must not be
# handed to a box that cannot start it. (update.sh takes the same lock for itself.)
mkdir -p "$DATA"
if ! flock -n "$DATA/update.lock" true; then
  echo "an update is running; asking next time"
  exit 0
fi

if ! answer=$(ask); then
  echo "the relay did not answer on $BASE (stopped, starting, or this box's token is not its own)"
  exit 0
fi
# Digits and one word, nothing else, out of the answer.
id=$(printf '%s' "$answer" | grep -o '"request":{"id":[0-9]*' | grep -o '[0-9]*$')
to=$(printf '%s' "$answer" | grep -o '"to_build":[0-9]\{12\}[,}]' | grep -o '[0-9]\{12\}')
auto=$(printf '%s' "$answer" | grep -o '"auto":"\(off\|all\|security\)"' | cut -d'"' -f4)

if [ -z "$NIGHTLY" ]; then
  [ -n "$id" ] && [ -n "$to" ] || exit 0
  echo "the owner asked for build $to (request $id)"
  rm -f "$RESULT"
  bash "$UPDATE_SH" --signed --to "$to"
  rc=$?
  code=no-result; [ "$rc" = 3 ] && code=busy
  report "$(result_json "$id" "$code")"
  exit 0
fi

case "$auto" in
  all) flags=(--signed) ;;
  security) flags=(--signed --only-security) ;;
  *) exit 0 ;;
esac
echo "nightly update ($auto)"
rm -f "$RESULT"
bash "$UPDATE_SH" "${flags[@]}"
# Nothing done is nothing to tell: already there, not a security release, a newer build runs, or
# no channel is published yet.
if grep -q '"code":"\(already\|not-security\|newer-running\|no-manifest\)"' "$RESULT" 2>/dev/null; then
  exit 0
fi
report "$(result_json "" no-result)"
