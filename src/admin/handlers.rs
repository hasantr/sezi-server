use crate::auth::middleware::{fetch_role, require_admin, require_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct CreateInviteBody {
    email_hint: Option<String>,
    ttl_hours: Option<u64>,
}

pub async fn create_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: CreateInviteBody = req.json().await.unwrap_or_default();
    // `email_hint` artık serbest-metin ETİKET/İSİM (opsiyonel; admin daveti kimin için
    // ürettiğini not eder). Redeem'de e-posta ile EŞLEŞTİRİLMEZ (bkz invite.rs — eski
    // email-bind kaldırıldı; sentetik u...@sezgi.local e-postalarıyla zaten işlevsizdi).
    // `@` şartı KALDIRILDI (isim/etiket serbest); yalnız uzunluk sınırı (DoS koruması).
    if let Some(h) = &body.email_hint {
        if h.len() > 254 {
            return json_err(400, "bad_request");
        }
    }
    if let Some(t) = body.ttl_hours {
        if !(1..=24 * 30).contains(&t) {
            return json_err(400, "bad_request");
        }
    }

    let now = now_secs();
    let ttl = body.ttl_hours.unwrap_or(24) * 60 * 60;
    let token = random_b64u(18); // 24 char b64u
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO invite_tokens (token, email_hint, used, used_by, owner_user_id, expires_at, created_at)
         VALUES (?, ?, 0, NULL, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&token),
        d1_opt_text(body.email_hint.as_deref()),
        d1_text(&user_id),
        d1_int((now + ttl) as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "token": token,
        "email_hint": body.email_hint,
        "expires_at": now + ttl,
        "created_at": now,
    }))
}

#[derive(Deserialize)]
struct InviteRow {
    token: String,
    email_hint: Option<String>,
    used: i32,
    used_by: Option<String>,
    owner_user_id: Option<String>,
    used_by_email: Option<String>,
    owner_email: Option<String>,
    expires_at: i64,
    created_at: i64,
}

pub async fn list_invites(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    // Kim üretti (owner_email) + kim kullandı (used_by_email) JOIN ile çözülür.
    let rows: Vec<InviteRow> = db
        .prepare(
            "SELECT it.token, it.email_hint, it.used, it.used_by, it.owner_user_id,
                    ub.email AS used_by_email, ob.email AS owner_email,
                    it.expires_at, it.created_at
             FROM invite_tokens it
             LEFT JOIN users ub ON it.used_by = ub.id
             LEFT JOIN users ob ON it.owner_user_id = ob.id
             ORDER BY it.created_at DESC LIMIT 100",
        )
        .all()
        .await?
        .results()?;
    let now = now_secs();
    let invites: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "token": r.token,
                "email_hint": r.email_hint,
                "used": r.used == 1,
                "used_by": r.used_by,
                "used_by_email": r.used_by_email,
                "owner_user_id": r.owner_user_id,
                "owner_email": r.owner_email,
                "expires_at": r.expires_at,
                "created_at": r.created_at,
                "expired": (r.expires_at as u64) <= now,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "invites": invites }))
}

#[derive(Deserialize, Default)]
struct UpdateSettingsBody {
    name: Option<String>,
    join_mode: Option<String>,
    retention_days: Option<i64>,
    /// Mesaj bekletme süresi (gün) — teslim edilmeyen mesaj DO `pending`
    /// kuyruğunda en çok kaç gün tutulur. None → mevcut korunur.
    message_retention_days: Option<i64>,
    /// Kota Faz 1a: sunucu-toplam depolama cap'i (byte). Konvansiyon:
    /// 0 = cap'i TEMİZLE (NULL = sınırsız), > 0 = set, None → mevcut korunur.
    max_storage_bytes: Option<i64>,
    /// Kota Faz 1a: per-user depolama cap'i (byte) — aynı 0-temizle konvansiyonu.
    max_user_storage_bytes: Option<i64>,
    /// "Herkesten sil" penceresi (saat) — bir mesaj GÖNDERİLDİKTEN sonra en çok
    /// kaç saat içinde "herkesten sil" yapılabilir (owner-ayarlı, DEFAULT 48).
    /// Alıcı taraf ileride ZORLAR; server yalnız değeri taşır. None → mevcut
    /// korunur (retention deseninin ikizi).
    delete_window_hours: Option<i64>,
}

pub async fn update_settings(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: UpdateSettingsBody = req.json().await.unwrap_or_default();
    if body.name.is_none()
        && body.join_mode.is_none()
        && body.retention_days.is_none()
        && body.message_retention_days.is_none()
        && body.max_storage_bytes.is_none()
        && body.max_user_storage_bytes.is_none()
        && body.delete_window_hours.is_none()
    {
        return json_err(400, "bad_request");
    }
    if let Some(n) = &body.name {
        if n.is_empty() || n.len() > 64 {
            return json_err(400, "bad_request");
        }
    }
    if let Some(m) = &body.join_mode {
        if m != "open" && m != "invite_only" {
            return json_err(400, "bad_request");
        }
    }
    if let Some(d) = body.retention_days {
        if !(1..=3650).contains(&d) {
            return json_err(400, "bad_request");
        }
    }
    if let Some(d) = body.message_retention_days {
        if !(1..=365).contains(&d) {
            return json_err(400, "bad_request");
        }
    }
    // "Herkesten sil" penceresi (saat): min 1 (retention gibi 0-belirsizliğinden
    // kaçın), max 8760 = 365 gün (message_retention 365-gün ruhunun saat-ikizi).
    if let Some(h) = body.delete_window_hours {
        if !(1..=8760).contains(&h) {
            return json_err(400, "bad_request");
        }
    }
    // Kota cap doğrulaması: negatif anlamsız (0 = temizle, > 0 = set).
    if body.max_storage_bytes.is_some_and(|v| v < 0)
        || body.max_user_storage_bytes.is_some_and(|v| v < 0)
    {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    // Mevcut satırı oku, yoksa default kullan, eksik alanlar mevcudu korur.
    #[derive(Deserialize)]
    struct CurRow {
        name: String,
        join_mode: String,
        retention_days: i64,
        message_retention_days: i64,
        // Kota cap'leri — NULLABLE kolon (NULL = sınırsız).
        max_storage_bytes: Option<i64>,
        max_user_storage_bytes: Option<i64>,
        delete_window_hours: i64,
    }
    let cur: Option<CurRow> = db
        .prepare(
            "SELECT name, join_mode, retention_days, message_retention_days, \
             max_storage_bytes, max_user_storage_bytes, delete_window_hours \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first(None)
        .await?;
    let cur_name = cur.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| "Sezi".into());
    let cur_mode = cur
        .as_ref()
        .map(|c| c.join_mode.clone())
        .unwrap_or_else(|| "invite_only".into());
    let cur_retention = cur.as_ref().map(|c| c.retention_days).unwrap_or(30);
    let cur_msg_retention = cur.as_ref().map(|c| c.message_retention_days).unwrap_or(30);
    let cur_max_storage = cur.as_ref().and_then(|c| c.max_storage_bytes);
    let cur_max_user_storage = cur.as_ref().and_then(|c| c.max_user_storage_bytes);
    let cur_delete_window = cur.as_ref().map(|c| c.delete_window_hours).unwrap_or(48);
    let new_name = body.name.unwrap_or(cur_name);
    let new_mode = body.join_mode.unwrap_or(cur_mode);
    let new_retention = body.retention_days.unwrap_or(cur_retention);
    let new_msg_retention = body.message_retention_days.unwrap_or(cur_msg_retention);
    // Kota cap efektif değeri: 0 → NULL (temizle = sınırsız), > 0 → set,
    // alan gelmemişse mevcut korunur.
    let new_max_storage = body
        .max_storage_bytes
        .map(|v| if v == 0 { None } else { Some(v) })
        .unwrap_or(cur_max_storage);
    let new_max_user_storage = body
        .max_user_storage_bytes
        .map(|v| if v == 0 { None } else { Some(v) })
        .unwrap_or(cur_max_user_storage);
    let new_delete_window = body.delete_window_hours.unwrap_or(cur_delete_window);

    db.prepare(
        "INSERT INTO server_settings \
            (id, name, join_mode, retention_days, message_retention_days, \
             max_storage_bytes, max_user_storage_bytes, delete_window_hours, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            join_mode = excluded.join_mode,
            retention_days = excluded.retention_days,
            message_retention_days = excluded.message_retention_days,
            max_storage_bytes = excluded.max_storage_bytes,
            max_user_storage_bytes = excluded.max_user_storage_bytes,
            delete_window_hours = excluded.delete_window_hours,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        d1_text(&new_name),
        d1_text(&new_mode),
        d1_int(new_retention),
        d1_int(new_msg_retention),
        d1_opt_int(new_max_storage),
        d1_opt_int(new_max_user_storage),
        d1_int(new_delete_window),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "name": new_name,
        "join_mode": new_mode,
        "retention_days": new_retention,
        "message_retention_days": new_msg_retention,
        "max_storage_bytes": new_max_storage,
        "max_user_storage_bytes": new_max_user_storage,
        "delete_window_hours": new_delete_window,
    }))
}

#[derive(Deserialize, Default)]
struct RevokeInviteBody {
    token: String,
}

/// Kullanılmamış bir daveti iptal et (admin). Kullanılmış davet silinmez.
pub async fn revoke_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: RevokeInviteBody = req.json().await.unwrap_or_default();
    if body.token.is_empty() || body.token.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM invite_tokens WHERE token = ? AND used = 0")
        .bind(&[d1_text(&body.token)])?
        .run()
        .await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct UserRow {
    id: String,
    email: String,
    display_name: Option<String>,
    role: String,
    created_at: i64,
    last_seen_at: Option<i64>,
}

/// Sunucu üyelerini listele (admin). Rol atama için owner bu listeyi kullanır.
pub async fn list_users(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let rows: Vec<UserRow> = db
        .prepare(
            "SELECT id, email, display_name, role, created_at, last_seen_at
             FROM users ORDER BY created_at ASC LIMIT 200",
        )
        .all()
        .await?
        .results()?;
    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "created_at": r.created_at,
                "last_seen_at": r.last_seen_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "members": members }))
}

#[derive(Deserialize, Default)]
struct SetRoleBody {
    user_id: String,
    role: String,
}

#[derive(Deserialize)]
struct RoleOnly {
    role: String,
}

/// Bir üyenin rolünü ata (yalnız owner). role ∈ {admin, member}.
/// owner ASLA değiştirilemez (hedef owner ise 403; owner kendini de düşüremez).
pub async fn set_role(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: SetRoleBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() || (body.role != "admin" && body.role != "member") {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    match target {
        None => return json_err(404, "user_not_found"),
        Some(r) if r.role == "owner" => return json_err(403, "owner_immutable"),
        _ => {}
    }
    db.prepare("UPDATE users SET role = ? WHERE id = ? AND role != 'owner'")
        .bind(&[d1_text(&body.role), d1_text(&body.user_id)])?
        .run()
        .await?;
    Response::from_json(&serde_json::json!({
        "user_id": body.user_id,
        "role": body.role,
    }))
}

#[derive(Deserialize, Default)]
struct RemoveMemberBody {
    user_id: String,
}

/// Bir üyeyi sunucudan çıkar (kick): hesabını + bağlı verisini siler.
///
/// **Yetki:** owner herkesi (owner hariç) çıkarabilir; admin yalnız `member`
/// çıkarabilir (admin başka admin'i veya owner'ı çıkaramaz → 403). Kendini bu
/// uçtan çıkaramaz (ayrılma ayrı akış → `cannot_remove_self`).
///
/// Silinen kullanıcının `refresh_token`'ı gider → istemcisi bir sonraki
/// relogin'de `no_identity` ile düşer (yapısal kick). "Yasak"(ban) ayrıca
/// invite_only ile yapısal: yeni davet olmadan geri giremez.
///
/// FK temizliği (hiçbiri CASCADE değil; sıra önemli — çocuklar önce):
/// invite_tokens used_by/owner_user_id → NULL, sonra prekey/mesaj/medya/token
/// satırları, en son users.
pub async fn remove_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: RemoveMemberBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    if body.user_id == caller {
        return json_err(403, "cannot_remove_self");
    }

    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    let target_role = match target {
        None => return json_err(404, "user_not_found"),
        Some(r) if r.role == "owner" => return json_err(403, "owner_immutable"),
        Some(r) => r.role,
    };
    // admin başka admin'i çıkaramaz — yalnız owner.
    let caller_role = match fetch_role(&caller, &ctx.env).await {
        Ok(Some(r)) => r,
        _ => return json_err(403, "forbidden"),
    };
    if caller_role == "admin" && target_role == "admin" {
        return json_err(403, "forbidden");
    }

    // FK referansları (CASCADE yok) — sıra: önce çocuk/ref satırlar, en son user.
    db.prepare("UPDATE invite_tokens SET used_by = NULL WHERE used_by = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("UPDATE invite_tokens SET owner_user_id = NULL WHERE owner_user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM signed_prekeys WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM pending_messages WHERE recipient_id = ? OR sender_id = ?")
        .bind(&[d1_text(&body.user_id), d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM media_objects WHERE uploader_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM push_tokens WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    // S10 (Fable MED — token-iptali / grup-enjeksiyon): users silinse + refresh_token
    // gitse de JWT access-token (≤15dk TTL, stateless → DB-kontrolsüz) o pencerede
    // GEÇERLİ kalır; group_members SİLİNMEDİĞİ için group_role hâlâ aktif → çıkarılan
    // üye o sürede grup mesajı ENJEKTE edebiliyor + fan-out alıyordu. Tüm gruplardan
    // çıkar → group_role None → messages/send grup yolu 403 (anında, token TTL'i
    // beklemeden). (1:1 JWT-penceresi ayrı/kabul: kısa TTL + sender users'tan silindi.)
    // FORWARD-SECRECY (SAĞLAMLAŞTIRMA 2026-06-25): kullanıcı TÜM gruplardan çıkarılıyor.
    // Etkilenen ODALARIN her biri için plugin `epoch_floor`'u bump et → çıkarılan üye eski
    // epoch ile server-log'a append EDEMEZ (409 epoch_stale) + kalan üyeler yeni-epoch'a
    // geçer (çıkarılanın bildiği eski anahtar gelecek-veriyi çözemez). Per-GRUP remove_member
    // (groups.rs) zaten bump ediyor; bu server-admin "tüm-gruptan-çıkar" yolu ATLIYORDU.
    // group_members SİLİNMEDEN ÖNCE oda listesini topla.
    #[derive(Deserialize)]
    struct GroupIdRow {
        group_id: String,
    }
    let affected: Vec<GroupIdRow> = db
        .prepare("SELECT group_id FROM group_members WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .all()
        .await?
        .results()
        .unwrap_or_default();
    db.prepare("DELETE FROM group_members WHERE user_id = ?")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM users WHERE id = ? AND role != 'owner'")
        .bind(&[d1_text(&body.user_id)])?
        .run()
        .await?;
    // best-effort: bump başarısız olsa da kick başarılı sayılır (membership-revoke zaten
    // append/sync'i kesti; floor ikinci savunma). Hata yutulmaz — loglanır.
    for g in &affected {
        if let Err(e) = crate::plugin_log::bump_epoch_floor(&db, &g.group_id).await {
            console_warn!("remove_member: epoch_floor bump fail room={}: {e:?}", g.group_id);
        }
    }

    Response::from_json(&serde_json::json!({ "ok": true, "removed": body.user_id }))
}

#[derive(Deserialize, Default)]
struct TransferBody {
    user_id: String,
}

/// Sahipliği başka bir üyeye devret (yalnız owner). Yeni owner `owner` olur,
/// eski owner (caller) `admin`'e iner (erişimi korur, dışlanmaz). Tek-owner
/// kuralı korunur: D1 batch ile SIRALI iki statement — ÖNCE caller'ı admin'e
/// indir, SONRA new_owner'ı owner yap (ara durumda 0-owner olabilir ama ASLA
/// 2-owner → idx_one_owner partial-UNIQUE ihlali yok). Kendine devredilemez.
pub async fn transfer_ownership(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: TransferBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    if body.user_id == caller {
        return json_err(400, "already_owner");
    }
    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    if target.is_none() {
        return json_err(404, "user_not_found");
    }
    // Atomik takas: eski(caller) -> admin ÖNCE, sonra yeni -> owner.
    // FIX-1 (BLOCKER): Tek-statement CASE UPDATE + `idx_one_owner` (0018 partial-
    // UNIQUE WHERE role='owner') ÇAKIŞIYOR: SQLite `IN(...)`'i SIRALI tarar; eğer
    // new_owner_id leksikografik olarak caller'dan ÖNCE geliyorsa, satır-satır UPDATE
    // ÖNCE new_owner'ı 'owner' yapar → o anda caller HÂLÂ owner → 2 owner → partial-
    // UNIQUE ihlali → "UNIQUE constraint failed: users.role" → 500 (UUID-sırasına bağlı
    // ~%50 deterministik-olmayan). FIX: D1 batch ile SIRALI İKİ statement (sıra GARANTİ):
    // ÖNCE caller'ı 'admin'e indir (owner sayısı 0'a düşer), SONRA new_owner'ı 'owner'
    // yap (owner sayısı tekrar 1) → hiçbir an 2-owner olmaz.
    db.batch(vec![
        db.prepare("UPDATE users SET role = 'admin' WHERE id = ?")
            .bind(&[d1_text(&caller)])?,
        db.prepare("UPDATE users SET role = 'owner' WHERE id = ?")
            .bind(&[d1_text(&body.user_id)])?,
    ])
    .await?;
    Response::from_json(&serde_json::json!({
        "ok": true,
        "new_owner": body.user_id,
        "former_owner": caller,
    }))
}
