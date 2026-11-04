# Sezi Server — Lite (without files)

This folder is the Sezi server **without a file store**. It exists for one case: a Cloudflare
account where you will not turn R2 on (Cloudflare asks for a payment card to enable it, even for
the free 10 GB). The normal install, one folder up, includes files and is what the Sezi app
recommends.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/hasantr/sezi-server/tree/main/lite)

**What works:** messaging, groups and calls.
**What does not:** photos, files, voice messages, the group library and installing apps into a
group (their code is kept in the same store) — every upload is refused
(`503 media_not_configured`), and the server says `media: false` on `/capabilities`. The Sezi app
shows the owner "Files are off on this server" with the fix, until you either give the server a
store or tell the app to keep files off.

## Turning files on later — no reinstall

Either of these, whenever you like:

- **Cloudflare R2:** dashboard → **R2** → turn it on → create a bucket named `sezi-media` → Workers
  & Pages → your server → **Settings → Bindings → Add → R2 bucket**, variable name `MEDIA`, bucket
  `sezi-media` → **Deploy**. Then press "Check again" in the app.
- **Any S3-compatible store, no card:** in the app, as owner → Server → **Storage** → add a store
  (Backblaze B2 has 10 GB free without a card).

A binding added only in the dashboard is not in your copy's `wrangler.toml`, and a later deploy
from that file may drop it. When you update with `scripts/update-from-upstream.sh`, run it as
`SEZI_MEDIA_BUCKET=sezi-media bash` (your bucket's name) so the update writes the binding into
the file.

Everything else — the claim key, updating, removing an installation — is as in the main
[README](../README.md).

This folder is generated: `wrangler.toml` here is the main one with its R2 block removed, and
`build/` is the same prebuilt server. Do not edit it in the template repository; it is rebuilt
from the Sezi monorepo by `worker-rs/scripts/template-lite.sh`.
