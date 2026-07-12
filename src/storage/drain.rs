//! Drain/taşıma motoru (Faz 4, plan c.4 "TAŞIMA") — `draining` depodaki blob'ları
//! kalan aktif depolara taşır; envanter 0'a inince depoyu otomatik `disabled` yapar.
//!
//! KOŞUM YOLU: 2dk-cron (`lib.rs scheduled`, her invocation) + lazy-maintenance sırtı
//! (`maintenance.rs` claim-anahtarı `maint_storage_move_at`). Koşum başına
//! ≤`MOVE_BATCH` blob — free-plan subrequest bütçesi: blob başına GET+PUT+2×D1+DELETE
//! ≈ 5 çağrı → 4 blob ≈ 20, güvenli (plan c.4). Blob-bazlı idempotent: yarıda kalırsa
//! sonraki koşum kaldığı yerden (meta'sı hâlâ kaynağı gösteren blob'lar aday kalır).
//!
//! GÜVENCELER:
//! - **Yarış-koruması (plan f#8):** meta-güncelleme KOŞULLU
//!   (`... AND store_id=<kaynak>` + RETURNING). 0 satır = ack/TTL blob'u bu arada
//!   sildi → hedefe kopyalanan blob `storage_orphans` tombstone'una (günlük retry
//!   siler) → çift-kopya/çift-sayım imkânsız. 0-satırın İKİNCİ olası nedeni (eşzamanlı
//!   ikinci koşum aynı hedefe taşıdı / UPDATE geçici hata) için orphan'lamadan önce
//!   meta'nın ŞU AN nereyi gösterdiğine bakılır (`race_action`): meta==hedef →
//!   kopyamız kanonik, DOKUNMA (yanlış-orphan = kanonik blob'u tombstone'a yollamak
//!   = veri kaybı; fail-safe yön = orphan'lamamak).
//! - **Kaynak ölürse (plan f#7):** get-Err → blob atlanır (kalan sayaç düşmez →
//!   panel `draining_remaining` üzerinden "taşıma takıldı" gösterir); depo dönünce
//!   kaldığı yerden.
//! - **Okuma kesintisiz (plan c.4):** meta hangi depoyu gösteriyorsa oradan okunur
//!   (router draining/disabled depoları da yükler) → taşınana dek eski, taşınınca
//!   yeni depodan; drain boyunca hiç 404 penceresi yok.

use std::collections::{BTreeMap, HashMap};

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use super::maint::insert_orphans;
use super::{invalidate_storage_cache, write_health, StorageClass, StorageRouter};
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

/// Koşum başına azami taşınan blob (plan c.4 free-plan subrequest bütçesi).
const MOVE_BATCH: usize = 4;

/// 3 meta-tablo UNION'ından gelen taşıma-adayı satırı (`candidates_sql`).
#[derive(Deserialize)]
struct MoveRow {
    chan: String, // 'media' | 'plugin_media' | 'plugin_code'
    room_id: String,
    blob_id: String,
    size_bytes: i64,
    store_id: String, // kaynak (draining) depo
}

/// Taşıma motoru tick'i — cron her invocation'da + lazy claim-kazananı çağırır.
/// Draining depo yoksa TEK ucuz SELECT ile sessiz çıkar. Blob-düzeyi hatalar
/// yutulur-atlanır (bir blob'un hatası batch'in kalanını kırmaz); yalnız D1/router
/// kurulum hataları Err döner (çağıran loglar).
pub(crate) async fn run_storage_move(env: &Env) -> Result<()> {
    let db = env.d1("DB")?;
    #[derive(Deserialize)]
    struct IdRow {
        store_id: String,
    }
    let draining: Vec<IdRow> = db
        .prepare("SELECT store_id FROM storage_backends WHERE state = 'draining' ORDER BY priority ASC")
        .all()
        .await?
        .results()?;
    if draining.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = draining.into_iter().map(|r| r.store_id).collect();

    // Adaylar: 3 meta-tablo UNION'ından draining-depolu EN ESKİ ≤MOVE_BATCH blob.
    let rows: Vec<MoveRow> = db
        .prepare(candidates_sql(ids.len()))
        .bind(&in_binds_x3(&ids))?
        .all()
        .await?
        .results()?;

    if !rows.is_empty() {
        // TAZE config ŞART (izolat-cache ≤60sn bayat olabilir): bayat cache draining
        // depoyu hâlâ 'active' gösterirse put_new blob'u KAYNAĞA geri yazardı (anahtar
        // aynı!) → ardından kaynak-delete = VERİ KAYBI. invalidate → from_env D1'den
        // taze okur → draining yerleştirme-dışı (router classify_placement).
        invalidate_storage_cache();
        let router = StorageRouter::from_env(env).await?;
        let mut moved: Vec<(String, String, i64)> = Vec::new(); // (kaynak, hedef, boyut)
        for row in &rows {
            match move_one(&db, &router, row).await {
                MoveOutcome::Moved { target, size } => {
                    moved.push((row.store_id.clone(), target, size));
                }
                MoveOutcome::Skipped => {}
                // Yerleştirme yok (kalan depolar dolu/kapalı): batch'in kalanı da aynı
                // sonuca varır → kes; sonraki koşum yeniden dener (panel kalan-sayaç
                // düşmediğinden "taşıma takıldı" gösterir — plan f#7 emsali).
                MoveOutcome::NoTarget => break,
            }
        }
        if !moved.is_empty() {
            transfer_counters(&db, &moved).await;
            console_log!("storage drain: {} blob taşındı", moved.len());
        }
    }

    // Bitiş-tespiti (plan c.4 "kalan 0"): envanteri boşalan draining depo otomatik
    // `disabled` + son health-notu. UPDATE koşullu (`AND state='draining'`): owner bu
    // arada PATCH'le durumu değiştirdiyse dokunulmaz.
    let remaining = remaining_counts(&db, &ids).await?;
    let now = now_secs() as i64;
    for id in &ids {
        if !drain_complete(remaining.get(id).copied().unwrap_or(0)) {
            continue;
        }
        if let Ok(stmt) = db
            .prepare(
                "UPDATE storage_backends SET state = 'disabled', updated_at = ? \
                 WHERE store_id = ? AND state = 'draining'",
            )
            .bind(&[d1_int(now), d1_text(id)])
        {
            let _ = stmt.run().await;
        }
        // Son health-notu (ok=true → panel kızarmaz; metin "taşıma bitti" izidir).
        write_health(env, id, true, Some("drain_complete")).await;
        invalidate_storage_cache();
        console_log!("storage drain: '{}' boşaldı → disabled", id);
    }
    Ok(())
}

/// Draining depo(lar)ın KALAN envanter sayıları (3 meta-tablo UNION sayımı).
/// Bitiş-tespiti + `GET /admin/storage` `draining_remaining` + drain-endpoint cevabı
/// ORTAK kullanır → "kalan" tanımı tek-yerde. İstenen her id sonuçta VAR (yoksa 0).
pub(crate) async fn remaining_counts(
    db: &D1Database,
    store_ids: &[String],
) -> Result<HashMap<String, i64>> {
    let mut out: HashMap<String, i64> = store_ids.iter().map(|s| (s.clone(), 0)).collect();
    if store_ids.is_empty() {
        return Ok(out);
    }
    #[derive(Deserialize)]
    struct Row {
        store_id: String,
        c: i64,
    }
    let rows: Vec<Row> = db
        .prepare(remaining_sql(store_ids.len()))
        .bind(&in_binds_x3(store_ids))?
        .all()
        .await?
        .results()?;
    for r in rows {
        out.insert(r.store_id, r.c);
    }
    Ok(out)
}

// ── Tek blob taşıma ───────────────────────────────────────────────────────────

enum MoveOutcome {
    /// Taşındı: meta hedefi gösteriyor; kaynak silindi (ya da tombstone'da).
    Moved { target: String, size: i64 },
    /// Bu blob atlandı (kaynak-hatası / hayalet-meta / yarış) — batch devam eder.
    Skipped,
    /// Hiç hedef yerleştirilemedi (kalan depolar dolu/kapalı) — batch kesilir.
    NoTarget,
}

async fn move_one(db: &D1Database, router: &StorageRouter, row: &MoveRow) -> MoveOutcome {
    let Some((key, class)) = key_and_class(&row.chan, &row.room_id, &row.blob_id) else {
        return MoveOutcome::Skipped; // bilinmeyen kanal (olmamalı) — atla
    };
    // 1. Kaynaktan oku. Err = depo down / resolve-fail (plan f#7): blob atlanır
    //    (router.get fırsatçı health-işaretini zaten yaptı); depo dönünce kaldığı yerden.
    let obj = match router.get(&row.store_id, &key).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            // Hayalet-meta: satır var, blob fiziksel YOK (okuma da 404'lerdi). Koşullu
            // meta-DELETE ile düşür → drain ilerler (yoksa created_at ASC hep aynı
            // hayaletleri seçerdi = drain sonsuza dek takılırdı). Kota/per-depo sayaç
            // drift'ini günlük reconcile onarır (meta-tabanlı yeniden-hesap).
            phantom_meta_delete(db, row).await;
            console_warn!("storage drain: kaynakta yok, meta düşürüldü: {key}");
            return MoveOutcome::Skipped;
        }
        Err(_) => return MoveOutcome::Skipped,
    };
    let size = obj.bytes.len() as i64; // gerçek boyut (meta drift'ine karşı sayaç-aktarımı bunu kullanır)
    // 2. Kalan depolara yerleştir — AYNI anahtar (mod.rs anahtar-şeması backend-agnostik
    //    → taşıma = kopyala, anahtar değişmez). put_new yalnız 'active' depolara yazar
    //    → draining kaynak aday DEĞİL.
    let target = match router.put_new(class, &key, obj.bytes, &obj.content_type).await {
        Ok(t) => t,
        Err(_) => return MoveOutcome::NoTarget,
    };
    if target == row.store_id {
        // Savunma-hattı (normalde imkânsız: draining 'active' değil): hedef=kaynak ise
        // delete'e İNME — aynı-anahtar silme veri kaybı olurdu.
        return MoveOutcome::Skipped;
    }
    // 3. Koşullu meta-UPDATE (yarış-koruması, plan f#8): yalnız hâlâ kaynağı gösteren
    //    satır güncellenir.
    match after_copy(conditional_meta_update(db, row, &target).await) {
        AfterCopy::OrphanTargetCopy => {
            // 0 satır: meta ya silindi (ack/TTL yarışı) ya eşzamanlı koşum taşıdı ya da
            // UPDATE geçici hata yedi → orphan kararını meta'nın ŞU ANKİ durumuna bağla.
            if race_action(&meta_store_now(db, row).await, &target)
                == RaceAction::OrphanTargetCopy
            {
                insert_orphans(db, &[(target, key, row.size_bytes)]).await;
            }
            MoveOutcome::Skipped
        }
        AfterCopy::DeleteSource => {
            // 4. Kaynaktan sil; silinemezse tombstone (plan c.4) — meta zaten hedefi
            //    gösteriyor, kaynak kopyası öksüz-izlenir; taşıma İLERLEMİŞ sayılır.
            if router.delete(&row.store_id, &key).await.is_err() {
                insert_orphans(db, &[(row.store_id.clone(), key.clone(), row.size_bytes)]).await;
            }
            MoveOutcome::Moved { target, size }
        }
    }
}

/// Koşullu meta-UPDATE'i koş → tam 1 satır güncellendi mi (RETURNING sayımı —
/// maintenance.rs claim kazanan-deseni). Hata → false (güncellenmedi say; karar
/// `race_action` meta-bakışıyla verilir → yanlış yönde orphan üretmez).
async fn conditional_meta_update(db: &D1Database, row: &MoveRow, target: &str) -> bool {
    #[derive(Deserialize)]
    struct Ret {
        #[allow(dead_code)]
        blob_id: String,
    }
    let Some(sql) = meta_update_sql(&row.chan) else {
        return false;
    };
    let mut binds = vec![d1_text(target)];
    binds.extend(key_binds(row));
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return false;
    };
    match stmt.all().await {
        Ok(res) => res.results::<Ret>().map(|r| r.len() == 1).unwrap_or(false),
        Err(_) => false,
    }
}

/// Hayalet-meta koşullu DELETE (best-effort): yalnız hâlâ kaynağı gösteren satır
/// düşer — eşzamanlı koşum bu arada taşıdıysa (meta=hedef) DOKUNULMAZ.
async fn phantom_meta_delete(db: &D1Database, row: &MoveRow) {
    let Some(sql) = meta_delete_sql(&row.chan) else {
        return;
    };
    if let Ok(stmt) = db.prepare(sql).bind(&key_binds(row)) {
        let _ = stmt.run().await;
    }
}

/// Meta satırı ŞU AN hangi depoyu gösteriyor? (yarış-sonrası orphan kararı için.)
async fn meta_store_now(db: &D1Database, row: &MoveRow) -> MetaNow {
    #[derive(Deserialize)]
    struct S {
        store_id: String,
    }
    let Some(sql) = meta_select_sql(&row.chan) else {
        return MetaNow::Unknown;
    };
    let binds: Vec<JsValue> = if row.chan == "media" {
        vec![d1_text(&row.blob_id)]
    } else {
        vec![d1_text(&row.room_id), d1_text(&row.blob_id)]
    };
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return MetaNow::Unknown;
    };
    match stmt.first::<S>(None).await {
        Ok(Some(s)) => MetaNow::PointsTo(s.store_id),
        Ok(None) => MetaNow::Gone,
        Err(_) => MetaNow::Unknown,
    }
}

/// used_bytes/object_count sayaç-aktarımı (best-effort, plan c.4; drift'i günlük
/// reconcile onarır). Tek `db.batch` = tek subrequest; 0-clamp (usage.rs disiplini).
async fn transfer_counters(db: &D1Database, moved: &[(String, String, i64)]) {
    let now = now_secs() as i64;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for (store_id, d_bytes, d_count) in counter_deltas(moved) {
        if let Ok(stmt) = db
            .prepare(
                "UPDATE storage_backends SET used_bytes = MAX(0, used_bytes + ?), \
                 object_count = MAX(0, object_count + ?), updated_at = ? WHERE store_id = ?",
            )
            .bind(&[d1_int(d_bytes), d1_int(d_count), d1_int(now), d1_text(&store_id)])
        {
            stmts.push(stmt);
        }
    }
    if !stmts.is_empty() {
        let _ = db.batch(stmts).await;
    }
}

/// Kanalın anahtar-bindleri: media=[blob,kaynak]; plugin_*=[room,blob,kaynak]
/// (`meta_update_sql`/`meta_delete_sql` WHERE sırasıyla birebir).
fn key_binds(row: &MoveRow) -> Vec<JsValue> {
    if row.chan == "media" {
        vec![d1_text(&row.blob_id), d1_text(&row.store_id)]
    } else {
        vec![
            d1_text(&row.room_id),
            d1_text(&row.blob_id),
            d1_text(&row.store_id),
        ]
    }
}

/// IN-listesi bindleri 3 tablo için tekrarlı (candidates_sql/remaining_sql ile birebir).
fn in_binds_x3(ids: &[String]) -> Vec<JsValue> {
    let mut binds = Vec::with_capacity(ids.len() * 3);
    for _ in 0..3 {
        for id in ids {
            binds.push(d1_text(id));
        }
    }
    binds
}

// ── Saf çekirdek (unit-testli; worker türlerinden bağımsız) ───────────────────

/// Taşıma-adayı → (depo-anahtarı, yerleştirme-sınıfı). Anahtar-şeması mod.rs'in
/// tek-gerçeği (`media_key`/`plugin_media_key`/`code_key`) — her depo AYNI anahtarı
/// kullanır. Bilinmeyen kanal → None (atla).
fn key_and_class(chan: &str, room_id: &str, blob_id: &str) -> Option<(String, StorageClass)> {
    match chan {
        "media" => Some((super::media_key(blob_id), StorageClass::Media)),
        "plugin_media" => Some((
            super::plugin_media_key(room_id, blob_id),
            StorageClass::PluginMedia,
        )),
        "plugin_code" => Some((super::code_key(room_id, blob_id), StorageClass::PluginCode)),
        _ => None,
    }
}

/// Kanal → koşullu meta-UPDATE (yarış-koruması: `AND store_id = ?` + RETURNING;
/// binds: [hedef] + `key_binds`). Bilinmeyen kanal → None.
fn meta_update_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some(
            "UPDATE media_objects SET store_id = ? \
             WHERE blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        "plugin_media" => Some(
            "UPDATE plugin_media_objects SET store_id = ? \
             WHERE room_id = ? AND blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        "plugin_code" => Some(
            "UPDATE plugin_code_objects SET store_id = ? \
             WHERE room_id = ? AND blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        _ => None,
    }
}

/// Kanal → hayalet-meta koşullu DELETE (binds: `key_binds`).
fn meta_delete_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some("DELETE FROM media_objects WHERE blob_id = ? AND store_id = ?"),
        "plugin_media" => Some(
            "DELETE FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? AND store_id = ?",
        ),
        "plugin_code" => Some(
            "DELETE FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? AND store_id = ?",
        ),
        _ => None,
    }
}

/// Kanal → meta şu-an-nerede SELECT'i (binds: media=[blob]; plugin_*=[room,blob]).
fn meta_select_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some("SELECT store_id FROM media_objects WHERE blob_id = ? LIMIT 1"),
        "plugin_media" => Some(
            "SELECT store_id FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1",
        ),
        "plugin_code" => Some(
            "SELECT store_id FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? LIMIT 1",
        ),
        _ => None,
    }
}

/// Koşullu-UPDATE sonucu → kopya-sonrası eylem (SAF; plan f#8):
/// 1 satır = meta artık hedefi gösteriyor → kaynak silinir;
/// 0 satır = yarış-şüphesi → hedefteki kopyanın kaderi `race_action`la belirlenir.
#[derive(Debug, PartialEq)]
enum AfterCopy {
    DeleteSource,
    OrphanTargetCopy,
}

fn after_copy(meta_updated: bool) -> AfterCopy {
    if meta_updated {
        AfterCopy::DeleteSource
    } else {
        AfterCopy::OrphanTargetCopy
    }
}

/// Meta satırının koşullu-UPDATE-sonrası anlık durumu.
#[derive(Debug, PartialEq)]
enum MetaNow {
    /// Satır yok — ack/TTL yarışı blob'u sildi.
    Gone,
    /// Satır var, şu depoyu gösteriyor.
    PointsTo(String),
    /// D1 okunamadı (geçici hata).
    Unknown,
}

/// 0-satır yarışında hedef-kopya kararı (SAF): yalnız meta'nın hedefi GÖSTERMEDİĞİ
/// POZİTİF tespitle orphan'lanır. meta==hedef → eşzamanlı koşum aynı hedefe taşıdı,
/// kopyamız KANONİK → dokunma. Unknown → fail-safe DOKUNMA (yanlış-orphan = kanonik
/// blob'u tombstone'a yollamak = veri kaybı; sahipsiz kopya en kötü hedefte byte
/// olarak kalır, veri kaybettirmez).
#[derive(Debug, PartialEq)]
enum RaceAction {
    OrphanTargetCopy,
    LeaveTargetCopy,
}

fn race_action(meta_now: &MetaNow, target: &str) -> RaceAction {
    match meta_now {
        MetaNow::Gone => RaceAction::OrphanTargetCopy,
        MetaNow::PointsTo(s) if s == target => RaceAction::LeaveTargetCopy,
        MetaNow::PointsTo(_) => RaceAction::OrphanTargetCopy,
        MetaNow::Unknown => RaceAction::LeaveTargetCopy,
    }
}

/// Bitiş-tespiti (SAF): draining depoda envanter kalmadı → otomatik `disabled`.
fn drain_complete(remaining: i64) -> bool {
    remaining <= 0
}

/// n-adet draining depo için taşıma-adayı SQL'i: 3 meta-tablo UNION, en eski önce,
/// ≤MOVE_BATCH. Binds = `in_binds_x3` (id listesi 3 kez).
fn candidates_sql(n_stores: usize) -> String {
    let marks = placeholders(n_stores);
    format!(
        "SELECT 'media' AS chan, '' AS room_id, blob_id, size_bytes, store_id, created_at \
           FROM media_objects WHERE store_id IN ({marks}) \
         UNION ALL \
         SELECT 'plugin_media' AS chan, room_id, blob_id, size_bytes, store_id, created_at \
           FROM plugin_media_objects WHERE store_id IN ({marks}) \
         UNION ALL \
         SELECT 'plugin_code' AS chan, room_id, blob_id, size_bytes, store_id, created_at \
           FROM plugin_code_objects WHERE store_id IN ({marks}) \
         ORDER BY created_at ASC LIMIT {MOVE_BATCH}"
    )
}

/// n-adet depo için kalan-envanter SQL'i (store_id bazında sayım). Binds = `in_binds_x3`.
fn remaining_sql(n_stores: usize) -> String {
    let marks = placeholders(n_stores);
    format!(
        "SELECT store_id, COUNT(*) AS c FROM ( \
           SELECT store_id FROM media_objects WHERE store_id IN ({marks}) \
           UNION ALL SELECT store_id FROM plugin_media_objects WHERE store_id IN ({marks}) \
           UNION ALL SELECT store_id FROM plugin_code_objects WHERE store_id IN ({marks}) \
         ) t GROUP BY store_id"
    )
}

fn placeholders(n: usize) -> String {
    (0..n).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// Taşınan (kaynak, hedef, boyut) listesi → per-depo (Δbytes, Δcount): kaynak eksi,
/// hedef artı; store_id-sıralı deterministik çıktı (SAF; `transfer_counters` tüketir).
fn counter_deltas(moved: &[(String, String, i64)]) -> Vec<(String, i64, i64)> {
    let mut map: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
    for (source, target, size) in moved {
        let e = map.entry(source.as_str()).or_insert((0, 0));
        e.0 -= size;
        e.1 -= 1;
        let e = map.entry(target.as_str()).or_insert((0, 0));
        e.0 += size;
        e.1 += 1;
    }
    map.into_iter()
        .map(|(k, (b, c))| (k.to_string(), b, c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Taşıma-adayı anahtar/sınıf eşlemesi mod.rs anahtar-şemasıyla bit-aynı
    /// (taşıma = kopyala, anahtar değişmez — Faz 4 ön-koşulu).
    #[test]
    fn aday_anahtar_ve_sinif_semasi() {
        let (k, c) = key_and_class("media", "", "b1").unwrap();
        assert_eq!(k, "media/b1");
        assert!(matches!(c, StorageClass::Media));
        let (k, c) = key_and_class("plugin_media", "r1", "b1").unwrap();
        assert_eq!(k, "plugin-media/r1/b1");
        assert!(matches!(c, StorageClass::PluginMedia));
        let (k, c) = key_and_class("plugin_code", "r1", "b1").unwrap();
        assert_eq!(k, "plugin-code/r1/b1");
        assert!(matches!(c, StorageClass::PluginCode));
        assert!(key_and_class("bogus", "r", "b").is_none());
    }

    /// Aday-SQL: 3 tablo × n placeholder (in_binds_x3 ile birebir), en-eski-önce,
    /// koşum-tavanı MOVE_BATCH.
    #[test]
    fn aday_sql_placeholder_siralama_limit() {
        let sql = candidates_sql(2);
        assert_eq!(sql.matches('?').count(), 6, "3 tablo × 2 id");
        assert!(sql.contains("ORDER BY created_at ASC"));
        assert!(sql.ends_with(&format!("LIMIT {MOVE_BATCH}")));
        assert!(sql.contains("FROM media_objects"));
        assert!(sql.contains("FROM plugin_media_objects"));
        assert!(sql.contains("FROM plugin_code_objects"));
    }

    /// Koşullu-UPDATE semantiği: her kanal SQL'i kaynak-koşullu (`AND store_id = ?`)
    /// ve RETURNING'li (0-satır yarış tespiti); hayalet-DELETE de koşullu.
    /// Bilinmeyen kanal → None (hiçbir koşulsuz mutasyon yolu yok).
    #[test]
    fn kosullu_update_yaris_korumasi() {
        for chan in ["media", "plugin_media", "plugin_code"] {
            let sql = meta_update_sql(chan).unwrap();
            assert!(sql.contains("AND store_id = ?"), "{chan}: koşulsuz UPDATE yasak");
            assert!(sql.contains("RETURNING blob_id"), "{chan}: yarış tespiti RETURNING ister");
            let del = meta_delete_sql(chan).unwrap();
            assert!(del.contains("store_id = ?"), "{chan}: hayalet-DELETE de koşullu");
            assert!(meta_select_sql(chan).is_some());
        }
        assert!(meta_update_sql("bogus").is_none());
        assert!(meta_delete_sql("bogus").is_none());
        assert!(meta_select_sql("bogus").is_none());
    }

    /// Koşullu-UPDATE sonucu → eylem: 1 satır = kaynak silinir; 0 satır = hedef
    /// kopya orphan-şüpheli (kararı race_action verir).
    #[test]
    fn kopya_sonrasi_eylem() {
        assert_eq!(after_copy(true), AfterCopy::DeleteSource);
        assert_eq!(after_copy(false), AfterCopy::OrphanTargetCopy);
    }

    /// Yarış-kararı (plan f#8 + eşzamanlı-koşum koruması): meta yok → orphan;
    /// meta başka depoda → orphan; meta==HEDEF → kanonik, DOKUNMA; D1 okunamadı →
    /// fail-safe DOKUNMA (yanlış-orphan = veri kaybı yönü).
    #[test]
    fn yaris_karari_fail_safe() {
        assert_eq!(
            race_action(&MetaNow::Gone, "r2-primary"),
            RaceAction::OrphanTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::PointsTo("s3-x".into()), "r2-primary"),
            RaceAction::OrphanTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::PointsTo("r2-primary".into()), "r2-primary"),
            RaceAction::LeaveTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::Unknown, "r2-primary"),
            RaceAction::LeaveTargetCopy
        );
    }

    /// Bitiş-tespiti: kalan 0 → depo drain'i bitti (otomatik disabled).
    #[test]
    fn bitis_tespiti() {
        assert!(drain_complete(0));
        assert!(!drain_complete(1));
        assert!(!drain_complete(87));
    }

    /// Sayaç-aktarımı: kaynak eksi / hedef artı, per-depo toplanır, store_id-sıralı.
    #[test]
    fn sayac_aktarimi_toplanir() {
        let moved = vec![
            ("s3-a".to_string(), "r2-primary".to_string(), 100),
            ("s3-a".to_string(), "r2-primary".to_string(), 50),
            ("s3-a".to_string(), "s3-b".to_string(), 7),
        ];
        let d = counter_deltas(&moved);
        assert_eq!(
            d,
            vec![
                ("r2-primary".to_string(), 150, 2),
                ("s3-a".to_string(), -157, -3),
                ("s3-b".to_string(), 7, 1),
            ]
        );
        assert!(counter_deltas(&[]).is_empty());
    }

    /// Kalan-envanter SQL'i: 3 tablo placeholder'ı + store bazında gruplama.
    #[test]
    fn kalan_sql_gruplu() {
        let sql = remaining_sql(1);
        assert_eq!(sql.matches('?').count(), 3);
        assert!(sql.contains("GROUP BY store_id"));
    }
}
