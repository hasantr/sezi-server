//! Depo-envanteri bakım işleri — günlük bakımdan (`maintenance::run_daily`) çağrılır.
//! `maintenance.rs`'in lazy-scheduling/cleanup çekirdeğinden AYRILDI (dosya-bütçesi + tek
//! sorumluluk): burada yalnız takılabilir-depolamaya özgü envanter işleri toplanır.
//!   - `insert_orphans` — TTL-cleanup'ta silinemeyen blob'lar → `storage_orphans` tombstone.
//!   - `retry_orphans`  — öksüz-blob tombstone'larını yeniden-sil (başaran düşer). Plan f#4.
//!   - `backfill_plugin_code` — eski `plugin-code/` blob'larını `plugin_code_objects`'e doldur.

use serde::Deserialize;
use worker::*;

use super::StorageRouter;
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

/// TTL-cleanup'ta silinemeyen blob'ları `storage_orphans` tombstone'una yaz (Faz 3, plan f#4).
/// İdempotent (`ON CONFLICT DO NOTHING` — aynı blob ikinci koşumda çift-satır üretmez).
/// Tek `db.batch` = tek subrequest. Best-effort: orphan-yazımı temizliği KIRMAZ.
pub(crate) async fn insert_orphans(db: &D1Database, orphans: &[(String, String, i64)]) {
    let now = now_secs() as i64;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for (store_id, key, size) in orphans {
        if let Ok(stmt) = db
            .prepare(
                "INSERT INTO storage_orphans (store_id, key, size_bytes, created_at, retry_count) \
                 VALUES (?, ?, ?, ?, 0) ON CONFLICT(store_id, key) DO NOTHING",
            )
            .bind(&[d1_text(store_id), d1_text(key), d1_int(*size), d1_int(now)])
        {
            stmts.push(stmt);
        }
    }
    if !stmts.is_empty() {
        let _ = db.batch(stmts).await;
    }
}

/// Öksüz-blob tombstone retry (Faz 3, plan f#4). En eski ≤50 orphan'ı router üzerinden
/// yeniden-sil: başarı (idempotent 204/404→Ok) → satır DÜŞER; başarısız (depo hâlâ down /
/// silinmiş-depo resolve-Err) → `retry_count++` (satır kalır, sonraki günde tekrar). Tek
/// batch = kaldır+artır tek subrequest. Router.delete TOPLU-yolda health-işaret yapmaz →
/// gürültü yok (owner elle/probe ile sağlığı görür).
pub(crate) async fn retry_orphans(env: &Env) -> Result<()> {
    #[derive(Deserialize)]
    struct OrphanRow {
        store_id: String,
        key: String,
    }
    let db = env.d1("DB")?;
    let rows: Vec<OrphanRow> = db
        .prepare("SELECT store_id, key FROM storage_orphans ORDER BY created_at ASC LIMIT 50")
        .all()
        .await?
        .results()?;
    if rows.is_empty() {
        return Ok(());
    }
    let router = StorageRouter::from_env(env).await?;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for r in rows {
        let stmt = if router.delete(&r.store_id, &r.key).await.is_ok() {
            db.prepare("DELETE FROM storage_orphans WHERE store_id=? AND key=?")
        } else {
            db.prepare(
                "UPDATE storage_orphans SET retry_count = retry_count + 1 \
                 WHERE store_id=? AND key=?",
            )
        };
        if let Ok(s) = stmt.bind(&[d1_text(&r.store_id), d1_text(&r.key)]) {
            stmts.push(s);
        }
    }
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    Ok(())
}

/// plugin-code/ R2 blob'larını `plugin_code_objects` envanterine geriye-doldur (Faz 1).
/// İdempotent (INSERT OR IGNORE → mevcut satırlar, örn. inline put_code meta'sı,
/// KORUNUR; yalnız eksikler eklenir; hepsi 'r2-primary'). R2 list sayfalı → cursor'la
/// sınırlı sayfa/koşum (free-plan subrequest bütçesi); günlük tekrar convergence sağlar.
/// Sayfa başına tek `db.batch` = tek subrequest (blob-başına ayrı INSERT değil).
pub(crate) async fn backfill_plugin_code(env: &Env) -> Result<()> {
    // Binding yoksa (Lite kurulum) R2 list imkânsız → sessiz çık (öksüz-envanter yok).
    let Ok(bucket) = env.bucket("MEDIA") else {
        return Ok(());
    };
    let db = env.d1("DB")?;
    let now = now_secs() as i64;
    // ≤5×1000 blob/koşum; eklenti-kodu pratikte az (admin-yükler) → çoğu kurulumda 1 sayfa.
    const MAX_PAGES: usize = 5;
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut listing = bucket.list().prefix("plugin-code/").limit(1000);
        if let Some(c) = cursor.take() {
            listing = listing.cursor(c);
        }
        let page = listing.execute().await?;
        let mut stmts: Vec<D1PreparedStatement> = Vec::new();
        for obj in page.objects() {
            let key = obj.key();
            let Some((room_id, blob_id)) = parse_code_key(&key) else {
                continue; // beklenmedik biçim → atla
            };
            // uploader_id backfill'de bilinmiyor → boş (NOT NULL'ı sağlar; envanter yeter).
            // INSERT OR IGNORE: gerçek uploader'lı inline-meta satırı varsa DOKUNULMAZ.
            let stmt = db
                .prepare(
                    "INSERT OR IGNORE INTO plugin_code_objects \
                     (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
                     VALUES (?, ?, ?, ?, 'r2-primary', ?)",
                )
                .bind(&[
                    d1_text(room_id),
                    d1_text(blob_id),
                    d1_text(""),
                    d1_int(obj.size() as i64),
                    d1_int(now),
                ])?;
            stmts.push(stmt);
        }
        if !stmts.is_empty() {
            db.batch(stmts).await?;
        }
        // Sonraki sayfa yalnız truncated + cursor varsa; yoksa bitti.
        match (page.truncated(), page.cursor()) {
            (true, Some(c)) => cursor = Some(c),
            _ => break,
        }
    }
    Ok(())
}

/// "plugin-code/{room}/{blob}" R2 anahtarından (room,blob) çıkar — `storage::code_key`
/// şemasıyla birebir. Beklenmedik biçim (eksik parça / blob'da '/') → None (atla).
fn parse_code_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("plugin-code/")?;
    let (room, blob) = rest.split_once('/')?;
    if room.is_empty() || blob.is_empty() || blob.contains('/') {
        return None;
    }
    Some((room, blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// plugin-code backfill anahtar-ayrıştırması: `storage::code_key` şemasıyla birebir
    /// ("plugin-code/{room}/{blob}"); beklenmedik biçimler atlanır (None).
    #[test]
    fn parse_code_key_semasi() {
        assert_eq!(
            parse_code_key("plugin-code/room1/blob1"),
            Some(("room1", "blob1"))
        );
        // Prefix yok / eksik parça / boş parça / blob'da fazladan '/' → None.
        assert_eq!(parse_code_key("media/abc"), None);
        assert_eq!(parse_code_key("plugin-code/roomonly"), None);
        assert_eq!(parse_code_key("plugin-code//blob"), None);
        assert_eq!(parse_code_key("plugin-code/room/"), None);
        assert_eq!(parse_code_key("plugin-code/room/sub/blob"), None);
    }
}
