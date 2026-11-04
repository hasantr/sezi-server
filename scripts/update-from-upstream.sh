#!/usr/bin/env bash
# Bring a "Deploy to Cloudflare" COPY of sezi-server up to date with github.com/hasantr/sezi-server.
#
# The Deploy button makes a copy, not a fork: a new repository with one commit and no history in
# common with this one. This script merges this repository into the copy and rebuilds the copy's
# wrangler.toml as THIS repository's file with only the copy's own deploy-time values put back:
#   - the Worker's `name`
#   - the D1 database (binding DB): `database_name`, `database_id`
#   - the KV namespace (binding RATE_LIMIT): `id`
#   - the R2 bucket (binding MEDIA): `bucket_name`
# Everything else in wrangler.toml — new bindings, variables, Durable Object migrations, the
# compatibility date — comes from here, so an update never strands the copy on an old config.
#
# Files (the R2 bucket MEDIA): a copy whose wrangler.toml binds MEDIA takes this repository's
# wrangler.toml with its own bucket name. A copy WITHOUT it — deployed from lite/, or from the
# template before 2026-11-04, when the bucket was left out — takes lite/wrangler.toml instead, so
# an update never adds a bucket the account may not be able to create (Cloudflare refuses a deploy
# naming R2 on an account where R2 is off). If you bound a bucket in the dashboard since, say so:
#   SEZI_MEDIA_BUCKET=<your bucket name>
# and the update writes the binding into wrangler.toml, where a later deploy cannot drop it.
#
# Run it inside a clone of YOUR copy, with a clean working tree:
#   git remote add upstream https://github.com/hasantr/sezi-server.git
#   git fetch upstream
#   git show upstream/main:scripts/update-from-upstream.sh | bash
#   git push
# It commits the merge and checks the result; the push is yours (it redeploys the server).
set -euo pipefail

UPSTREAM_URL="${SEZI_UPSTREAM:-https://github.com/hasantr/sezi-server.git}"
BRANCH="${SEZI_UPSTREAM_BRANCH:-main}"
UP="upstream/$BRANCH"

die() { echo "error: $*" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "run this inside your copy's folder"
cd "$(git rev-parse --show-toplevel)"
[ -f wrangler.toml ] || die "no wrangler.toml here — is this a sezi-server copy?"
[ -z "$(git status --porcelain)" ] || die "the folder has uncommitted changes; commit or discard them first"

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
git fetch --quiet upstream "$BRANCH"

if git merge-base --is-ancestor "$UP" HEAD 2>/dev/null; then
  echo "Already up to date with $UP."
  exit 0
fi

# toml_get FILE TABLE BINDING KEY — the value (as written, quotes included) of KEY in the block
# whose header is TABLE ("" = the top level) and, when BINDING is given, whose binding is it.
TOML_GET='
BEGIN { blk = 0 }
/^[ \t]*\[/ { cur = $0; gsub(/[ \t\[\]]/, "", cur); blk++; next }
/^[ \t]*[A-Za-z_]+[ \t]*=/ {
  k = $0; sub(/=.*/, "", k); gsub(/[ \t]/, "", k)
  v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v)
  val[blk, k] = v; tab[blk] = cur
}
END {
  for (b = 0; b <= blk; b++) {
    if (tab[b] != table) continue
    if (binding != "" && val[b, "binding"] != "\"" binding "\"") continue
    if ((b, key) in val) { print val[b, key]; exit }
  }
}'
toml_get() { awk -v table="$2" -v binding="$3" -v key="$4" "$TOML_GET" "$1"; }

# toml_set FILE TABLE BINDING KEY VALUE — rewrite that one line in place.
TOML_SET='
FNR == 1 { pass++; blk = 0; cur = "" }
/^[ \t]*\[/ { cur = $0; gsub(/[ \t\[\]]/, "", cur); blk++ }
pass == 1 {
  if ($0 ~ /^[ \t]*binding[ \t]*=/) { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); bind[blk] = v }
  tab[blk] = cur; next
}
{
  hit = (tab[blk] == table) && (binding == "" || bind[blk] == "\"" binding "\"")
  if (hit && $0 ~ ("^[ \t]*" key "[ \t]*=")) { print key " = " value; next }
  print
}'
toml_set() {
  local tmp
  tmp="$(mktemp)"
  awk -v table="$2" -v binding="$3" -v key="$4" -v value="$5" "$TOML_SET" "$1" "$1" >"$tmp"
  mv "$tmp" "$1"
}

# What only this copy knows, read BEFORE the merge touches anything.
OWN="$(mktemp)"; trap 'rm -f "$OWN"' EXIT
cp wrangler.toml "$OWN"
own_name="$(toml_get "$OWN" "" "" name)"
own_db_name="$(toml_get "$OWN" d1_databases DB database_name)"
own_db_id="$(toml_get "$OWN" d1_databases DB database_id)"
own_kv_id="$(toml_get "$OWN" kv_namespaces RATE_LIMIT id)"
own_bucket="$(toml_get "$OWN" r2_buckets MEDIA bucket_name)"
if [ -z "$own_bucket" ] && [ -n "${SEZI_MEDIA_BUCKET:-}" ]; then
  own_bucket="\"$SEZI_MEDIA_BUCKET\""
fi
[ -n "$own_db_id" ] || die "wrangler.toml has no database_id for the DB binding — nothing to keep"
case "$own_db_id" in *00000000-0000-0000-0000-000000000000*)
  die "wrangler.toml still has the template's placeholder database_id — was this copy ever deployed?";;
esac

# The merge: the first one joins two unrelated histories. `-X theirs` takes this repository's
# side wherever the two differ; wrangler.toml is rebuilt below either way.
first=""
git merge-base HEAD "$UP" >/dev/null 2>&1 || first="--allow-unrelated-histories"
# shellcheck disable=SC2086
if ! git merge --no-commit --no-ff -X theirs $first "$UP" >/dev/null; then
  unresolved="$(git diff --name-only --diff-filter=U | grep -vx 'wrangler.toml' || true)"
  if [ -n "$unresolved" ]; then
    git merge --abort
    die "the merge left conflicts outside wrangler.toml — nothing was changed:"$'\n'"$unresolved"
  fi
fi

# wrangler.toml = this repository's file + the copy's own values. A copy without files keeps
# lite/'s, where this repository has one (one from before lite/ existed had no bucket either).
UP_TOML="wrangler.toml"
lite_note=""
if [ -z "$own_bucket" ] && git cat-file -e "$UP:lite/wrangler.toml" 2>/dev/null; then
  UP_TOML="lite/wrangler.toml"
  lite_note="yes"
fi
git show "$UP:$UP_TOML" >wrangler.toml
[ -n "$own_name" ] && toml_set wrangler.toml "" "" name "$own_name"
[ -n "$own_db_name" ] && toml_set wrangler.toml d1_databases DB database_name "$own_db_name"
toml_set wrangler.toml d1_databases DB database_id "$own_db_id"
[ -n "$own_bucket" ] && toml_set wrangler.toml r2_buckets MEDIA bucket_name "$own_bucket"
kv_note=""
if [ -n "$own_kv_id" ]; then
  toml_set wrangler.toml kv_namespaces RATE_LIMIT id "$own_kv_id"
elif [ -n "$(toml_get wrangler.toml kv_namespaces RATE_LIMIT id)" ]; then
  kv_note="yes"
fi

# Check: the values are there, and nothing else differs from this repository's file.
[ "$(toml_get wrangler.toml d1_databases DB database_id)" = "$own_db_id" ] || die "database_id was not carried over"
[ -z "$own_kv_id" ] || [ "$(toml_get wrangler.toml kv_namespaces RATE_LIMIT id)" = "$own_kv_id" ] || die "the KV id was not carried over"
[ -z "$own_bucket" ] || [ "$(toml_get wrangler.toml r2_buckets MEDIA bucket_name)" = "$own_bucket" ] || die "the R2 bucket name was not carried over"
stray="$(diff <(git show "$UP:$UP_TOML") wrangler.toml | grep '^[<>]' | grep -vE '^[<>][ \t]*(name|database_name|database_id|id|bucket_name)[ \t]*=' || true)"
[ -z "$stray" ] || die "wrangler.toml differs from upstream in more than your own values:"$'\n'"$stray"

git add -A
git commit --quiet -m "Update from $UPSTREAM_URL ($(git rev-parse --short "$UP"))"
echo "Merged $UP. wrangler.toml is upstream's, with your own:"
diff <(git show "$UP:$UP_TOML") wrangler.toml | grep '^>' | sed 's/^> /    /' || true
if [ -n "$kv_note" ]; then
  cat <<'NOTE'

NOTE: your copy has no RATE_LIMIT KV namespace (it predates it), so wrangler.toml now names the
template's placeholder id and a deploy will fail until it is real. Create one — Cloudflare
dashboard → Storage & Databases → KV → Create, or `npx wrangler kv namespace create RATE_LIMIT` —
put its id on the `id = ` line under [[kv_namespaces]], then `git commit -am "KV id"`.
NOTE
fi
if [ -n "$lite_note" ]; then
  cat <<'NOTE'

NOTE: your copy binds no R2 bucket, so wrangler.toml is upstream's lite/ one — a server without
files (photos, files, voice messages and the group library are refused). If you bound a bucket as
MEDIA in the Cloudflare dashboard, that binding is not in this file and the next deploy may drop
it: undo this commit (`git reset --hard HEAD~1`) and run the update again as
`SEZI_MEDIA_BUCKET=<your bucket name> bash`. To turn files on, see lite/README.md.
NOTE
fi
echo
echo "Now: git push   (Cloudflare Workers Builds redeploys the server from the push)"
