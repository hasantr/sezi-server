//! The template a "Deploy to Cloudflare" server is made from (`template/wrangler.toml`, copied into
//! github.com/hasantr/sezi-server by `scripts/sync-template.sh`), held to what this worker reads.
//!
//! 2026-11-04: a review server deployed from the template had no `MEDIA` binding — the template
//! left R2 out on purpose — so `/capabilities` said `media:false` and every photo answered
//! `503 media_not_configured` for a week before anyone noticed. Files are now the default; a
//! server without them comes only from `lite/`, which `scripts/template-lite.sh` generates by
//! cutting the block between the media markers. No test runs a deploy, so these read the files.

const TEMPLATE: &str = include_str!("../template/wrangler.toml");
const LITE: &str = include_str!("../scripts/template-lite.sh");
const SYNC: &str = include_str!("../scripts/sync-template.sh");
const UPDATE: &str = include_str!("../template/scripts/update-from-upstream.sh");

/// The lines between the two markers, the block `lite/` leaves out.
fn media_block() -> Vec<&'static str> {
    let mut on = false;
    let mut block = Vec::new();
    for line in TEMPLATE.lines() {
        if line.starts_with("# >>> media") {
            on = true;
        } else if line.starts_with("# <<< media") {
            on = false;
        } else if on {
            block.push(line.trim());
        }
    }
    block
}

#[test]
fn a_fresh_deploy_binds_the_media_bucket() {
    let block = media_block();
    assert!(block.contains(&"[[r2_buckets]]"), "the R2 bucket is declared, not commented out");
    assert!(block.contains(&"binding = \"MEDIA\""), "under the name storage/ reads");
    assert!(block.iter().any(|l| l.starts_with("bucket_name = \"")));
    // Declared once, and only inside the markers: what lite/ cuts must be all of it.
    assert_eq!(TEMPLATE.matches("[[r2_buckets]]").count(), 1);
}

#[test]
fn the_template_keeps_every_binding_the_worker_reads() {
    for binding in [
        "binding = \"DB\"",
        "binding = \"RATE_LIMIT\"",
        "name = \"USER_INBOX\"",
        "name = \"PLUGIN_ROOM_LOG\"",
    ] {
        assert!(TEMPLATE.contains(binding), "{binding}");
        assert!(!media_block().contains(&binding), "{binding} must survive in lite/");
    }
}

#[test]
fn lite_is_generated_by_the_sync_and_checked_for_no_bucket() {
    assert!(SYNC.contains("scripts/template-lite.sh"), "the sync generates lite/");
    assert!(LITE.contains("# >>> media") && LITE.contains("# <<< media"));
    assert!(LITE.contains("still names an R2 bucket"), "and refuses a lite/ that keeps one");
}

#[test]
fn an_update_keeps_the_copys_bucket_and_never_adds_one_to_a_copy_without() {
    assert!(UPDATE.contains("r2_buckets MEDIA bucket_name"), "the bucket name is carried over");
    assert!(UPDATE.contains("lite/wrangler.toml"), "a copy without files stays without");
    assert!(UPDATE.contains("SEZI_MEDIA_BUCKET"), "a dashboard binding can be written in");
}
