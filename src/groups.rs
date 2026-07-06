//! Grup-sohbeti — üyelik + grup-içi yetki (Faz 1).
//!
//! Gruplar SUNUCU-içi alt-topluluklardır; grup-içi rol (owner/admin/member)
//! sunucu-rolünden BAĞIMSIZ (grubu kuran onda owner olur). AMA grup KURMA yetkisi
//! server OWNER'ına kısıtlıdır (Hasan 2026-07-03; `create_group` require_owner).
//! Bu bir "tanışma" mekanizması DEĞİL ([[directory-pairing-REJECTED]]): üye eklemek
//! için karşının `user_id`'sini ZATEN bilmen gerekir (1:1 eşleşmeden/dış kanaldan).
//!
//! E2E: sunucu grup İÇERİĞİNİ görmez. Bu modül yalnız üyelik tablosunu yönetir;
//! mesaj kriptosu Megolm (client), mesaj dağıtımı Faz 2 fan-out (messages).
//! Yetki matrisi server-authority epic'inin grup-ölçekli kopyası.

use crate::auth::middleware::{require_auth, require_owner};
use crate::d1util::{d1_int, d1_null, d1_opt_text, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

const MAX_NAME_CHARS: usize = 100;
const MAX_INITIAL_MEMBERS: usize = 200;
/// M12 (fan-out amplifikasyon — DoS): grup üye-sayısı tavanı. Her grup-send
/// fan-out'u N(üye × cihaz) DO-write üretir; üye-sayısı sınırsızsa tek mesaj
/// devasa amplifikasyon olur. add_member bu tavanı aşan eklemeyi 4xx ile reddeder.
/// MAX_INITIAL_MEMBERS (200) ile tutarlı, biraz üstünde makul tavan.
const MAX_GROUP_MEMBERS: usize = 256;

#[derive(Deserialize)]
struct GroupRoleRow {
    role: String,
}

/// Bir kullanıcının grup-içi rolü ('owner'|'admin'|'member') ya da AKTİF üye
/// değilse None. ÖNEMLİ (Faz 6 #3): yalnız `status='active'` üyeler sayılır —
/// 'pending' (henüz kabul etmemiş) davetliler üye DEĞİLDİR (mesaj alamaz/yönetemez/
/// üye-listesi göremez). `pub(crate)`: fan-out (messages::handlers::send) + tüm
/// grup-yetki kapıları bunu kullanır.
pub(crate) async fn group_role(
    db: &D1Database,
    group_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    let row: Option<GroupRoleRow> = db
        .prepare(
            "SELECT role FROM group_members
             WHERE group_id = ? AND user_id = ? AND status = 'active' LIMIT 1",
        )
        .bind(&[d1_text(group_id), d1_text(user_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.role))
}

/// Bir kullanıcının ham üyelik DURUMU ('pending'|'active') ya da satır yoksa None.
/// accept/decline davranışı buna bakar (group_role pending'i göremez).
async fn membership_status(
    db: &D1Database,
    group_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct StatusRow {
        status: String,
    }
    let row: Option<StatusRow> = db
        .prepare("SELECT status FROM group_members WHERE group_id = ? AND user_id = ? LIMIT 1")
        .bind(&[d1_text(group_id), d1_text(user_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.status))
}

pub(crate) fn is_group_admin(role: &str) -> bool {
    role == "owner" || role == "admin"
}

/// Geçerli `visibility` değeri mi? (ayar substratı — sunucunun ACT ettiği kolon).
/// Bilinmeyen değer reddedilir (forward-compat: yeni değer eklenince burası genişler).
fn valid_visibility(v: &str) -> bool {
    v == "private" || v == "public"
}

// ---------------------------------------------------------------------------
// POST /groups — grup oluştur (kurucu = group-owner). YETKİ (Hasan 2026-07-03): yalnız
// SERVER owner/admin grup kurabilir (eskiden HERHANGİ bir server üyesi kurabiliyordu →
// "herkes-grup-kurar" kaldırıldı). Opsiyonel member_ids ilk üyeleri ekler (zaten bilinen peer'lar).
// ---------------------------------------------------------------------------
#[derive(Deserialize, Default)]
struct CreateGroupBody {
    name: String,
    member_ids: Option<Vec<String>>,
    // Ayar torbası (substrat Faz 1) — hepsi opsiyonel; verilmezse şema-default'u.
    visibility: Option<String>,
    auto_join: Option<bool>,
    settings_json: Option<String>,
}

pub async fn create_group(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // YETKİ KAPISI (Hasan 2026-07-03, owner-only): grup kurma YALNIZ server OWNER'ı. Server-
    // otoriter (istemci baypas edemez; UI de gizler ama ASIL kapı burada). `users.role` =
    // 'owner'|'admin'|'member' (grup-içi rolden ayrı). Admin bile grup kuramaz (Hasan kararı).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: CreateGroupBody = req.json().await.unwrap_or_default();
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return json_err(400, "bad_name");
    }
    let members = body.member_ids.unwrap_or_default();
    if members.len() > MAX_INITIAL_MEMBERS {
        return json_err(400, "too_many_members");
    }
    // Ayar substratı: visibility validate (verilmezse 'private'); auto_join 0/1.
    let visibility = body.visibility.unwrap_or_else(|| "private".to_string());
    if !valid_visibility(&visibility) {
        return json_err(400, "bad_visibility");
    }
    let auto_join = if body.auto_join.unwrap_or(false) { 1 } else { 0 };
    let settings_json = body.settings_json; // opak; sunucu yorumlamaz

    let now = now_secs() as i64;
    let group_id = Uuid::new_v4().to_string();
    let db = ctx.env.d1("DB")?;

    db.prepare(
        "INSERT INTO groups (id, name, created_by, created_at, updated_at,
                             visibility, auto_join, settings_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&group_id),
        d1_text(&name),
        d1_text(&user_id),
        d1_int(now),
        d1_int(now),
        d1_text(&visibility),
        d1_int(auto_join),
        d1_opt_text(settings_json.as_deref()),
    ])?
    .run()
    .await?;

    // Kurucu = owner + AKTİF (kendi kurduğu gruba zaten katılmış sayılır).
    db.prepare(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status, added_by)
         VALUES (?, ?, 'owner', ?, 'active', NULL)",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id), d1_int(now)])?
    .run()
    .await?;

    // İlk üyeler (kurucu hariç) = member + PENDING (consent-first Faz 6 #3):
    // davet alır, kabul edene kadar üye SAYILMAZ. added_by = kurucu. INSERT OR
    // IGNORE → tekrar/çakışma yutulur.
    for m in members.iter().filter(|m| m.as_str() != user_id.as_str()) {
        let _ = db
            .prepare(
                "INSERT OR IGNORE INTO group_members
                    (group_id, user_id, role, joined_at, status, added_by)
                 VALUES (?, ?, 'member', ?, 'pending', ?)",
            )
            .bind(&[d1_text(&group_id), d1_text(m), d1_int(now), d1_text(&user_id)])?
            .run()
            .await;
    }

    Response::from_json(&serde_json::json!({
        "id": group_id,
        "name": name,
        "role": "owner",
        "created_at": now,
        "visibility": visibility,
        "auto_join": auto_join != 0,
        "settings_json": settings_json,
    }))
}

// ---------------------------------------------------------------------------
// GET /groups — üyesi olduğum gruplar (+ kendi rolüm + üye sayısı).
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct MyGroupRow {
    id: String,
    name: String,
    role: String,
    member_count: i64,
    created_at: i64,
    visibility: String,
    auto_join: i64,
    settings_json: Option<String>,
    status: String,
    added_by: Option<String>,
}

pub async fn list_my_groups(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    // status='pending' gruplar = aldığım DAVETLER (client ayırır). member_count
    // yalnız AKTİF üyeleri sayar (pending davetliler katılana kadar sayılmaz).
    let rows: Vec<MyGroupRow> = db
        .prepare(
            "SELECT g.id, g.name, gm.role,
                    (SELECT COUNT(*) FROM group_members x
                       WHERE x.group_id = g.id AND x.status = 'active') AS member_count,
                    g.created_at, g.visibility, g.auto_join, g.settings_json,
                    gm.status, gm.added_by
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = ?
             ORDER BY g.updated_at DESC LIMIT 200",
        )
        .bind(&[d1_text(&user_id)])?
        .all()
        .await?
        .results()?;
    let groups: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "role": r.role,
                "member_count": r.member_count,
                "created_at": r.created_at,
                "visibility": r.visibility,
                "auto_join": r.auto_join != 0,
                "settings_json": r.settings_json,
                "status": r.status,
                "added_by": r.added_by,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "groups": groups }))
}

// ---------------------------------------------------------------------------
// GET /groups/:id/members — grup üyeleri (yalnız üye görebilir).
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct MemberRow {
    user_id: String,
    email: Option<String>,
    display_name: Option<String>,
    role: String,
    joined_at: i64,
    status: String,
}

pub async fn group_members(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    if group_role(&db, &group_id, &user_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    let rows: Vec<MemberRow> = db
        .prepare(
            "SELECT gm.user_id, u.email, u.display_name, gm.role, gm.joined_at, gm.status
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = ?
             ORDER BY gm.joined_at ASC LIMIT 500",
        )
        .bind(&[d1_text(&group_id)])?
        .all()
        .await?
        .results()?;
    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "user_id": r.user_id,
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "joined_at": r.joined_at,
                "status": r.status,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "members": members }))
}

// ---------------------------------------------------------------------------
// POST /groups/:id/add-member — üye ekle (group owner/admin). body {user_id}.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct UserIdBody {
    user_id: String,
}

pub async fn add_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UserIdBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if is_group_admin(&role) => {}
        Some(_) => return json_err(403, "forbidden"),
        None => return json_err(403, "not_member"),
    }
    // M12 (fan-out amplifikasyon — DoS): üye-tavanı. Hedef ZATEN üye/davetliyse
    // (idempotent re-add → INSERT OR IGNORE no-op) tavanı uygulama (mevcut satır
    // büyütmüyor). Aksi halde grup-üye-sayısı (active+pending) MAX_GROUP_MEMBERS'a
    // ulaştıysa yeni ekleme 409 ile reddedilir. Pending de sayılır: kabul edilince
    // aktif olacak + fan-out genişliğini büyütür.
    if membership_status(&db, &group_id, &body.user_id).await?.is_none() {
        #[derive(Deserialize)]
        struct CountRow {
            c: i64,
        }
        let count: Option<CountRow> = db
            .prepare("SELECT COUNT(*) AS c FROM group_members WHERE group_id = ?")
            .bind(&[d1_text(&group_id)])?
            .first(None)
            .await?;
        if count.map(|r| r.c).unwrap_or(0) as usize >= MAX_GROUP_MEMBERS {
            return json_err(409, "group_full");
        }
    }
    let now = now_secs() as i64;
    // PENDING (consent-first Faz 6 #3): eklenen kişi davet alır, kabul edene kadar
    // üye SAYILMAZ (mesaj almaz). added_by = ekleyen → kabulde ona GroupJoinAccepted
    // gider, o anahtarı dağıtır. INSERT OR IGNORE → zaten üye/davetliyse no-op.
    db.prepare(
        "INSERT OR IGNORE INTO group_members
            (group_id, user_id, role, joined_at, status, added_by)
         VALUES (?, ?, 'member', ?, 'pending', ?)",
    )
    .bind(&[
        d1_text(&group_id),
        d1_text(&body.user_id),
        d1_int(now),
        d1_text(&requester),
    ])?
    .run()
    .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/accept — davet KABUL (pending → active; Faz 6 #3). Yalnız
// kendi pending satırını. Kabulden SONRA fan-out + anahtar akar (E2E consent).
// ---------------------------------------------------------------------------
pub async fn accept_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    match membership_status(&db, &group_id, &user_id).await? {
        Some(s) if s == "pending" => {}
        Some(_) => return no_content(), // zaten active → idempotent
        None => return json_err(404, "no_invite"),
    }
    db.prepare(
        "UPDATE group_members SET status = 'active'
         WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id)])?
    .run()
    .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/decline — davet RED (pending satırı sil; Faz 6 #3). Yalnız
// kendi pending davetini reddeder (active üyelik için "ayrıl" = remove-member).
// ---------------------------------------------------------------------------
pub async fn decline_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "DELETE FROM group_members
         WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id)])?
    .run()
    .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/remove-member — üye çıkar / gruptan ayrıl. body {user_id}.
// Yetki: kendi-ayrılma (owner hariç) serbest; başkasını çıkarma owner/admin;
// owner çıkarılamaz; admin başka admin'i çıkaramaz (server-authority deseni).
// ---------------------------------------------------------------------------
pub async fn remove_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UserIdBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let target = body.user_id;
    if target.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;

    let req_role = match group_role(&db, &group_id, &requester).await? {
        Some(r) => r,
        None => return json_err(403, "not_member"),
    };
    let target_role = match group_role(&db, &group_id, &target).await? {
        Some(r) => r,
        None => return no_content(), // zaten üye değil → idempotent
    };

    if target == requester {
        // Kendi-ayrılma: owner ayrılamaz (önce devret/grubu sil).
        if req_role == "owner" {
            return json_err(403, "owner_cannot_leave");
        }
    } else {
        // Başkasını çıkarma.
        if !is_group_admin(&req_role) {
            return json_err(403, "forbidden");
        }
        if target_role == "owner" {
            return json_err(403, "cannot_remove_owner");
        }
        // admin yalnız member çıkarır (başka admin'i değil); owner herkesi.
        if req_role == "admin" && target_role == "admin" {
            return json_err(403, "forbidden");
        }
    }

    db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
        .bind(&[d1_text(&group_id), d1_text(&target)])?
        .run()
        .await?;
    // FORWARD-SECRECY (Faz-D): kick / self-leave → eklenti server-log epoch FLOOR++ → çıkarılan
    // üye atılma-SONRASI ESKİ epoch'a yeni-veri append edemez (append-gate 409 epoch_stale).
    // Server KÖR (yalnız integer). Best-effort: hata olsa bile removal başarılı (no_content).
    let _ = crate::plugin_log::bump_epoch_floor(&db, &group_id).await;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/set-role — grup-içi rol ata (yalnız group-owner).
// body {user_id, role} ; role ∈ {admin, member} (owner ATANAMAZ/değiştirilemez).
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct SetRoleBody {
    user_id: String,
    role: String,
}

pub async fn set_role(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: SetRoleBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.role != "admin" && body.role != "member" {
        return json_err(400, "bad_role");
    }
    let db = ctx.env.d1("DB")?;
    // Yalnız group-owner rol atar.
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if role == "owner" => {}
        Some(_) => return json_err(403, "owner_required"),
        None => return json_err(403, "not_member"),
    }
    // Hedef üye olmalı + owner DEĞİL (owner rolü bu yoldan değişmez).
    match group_role(&db, &group_id, &body.user_id).await? {
        Some(role) if role == "owner" => return json_err(403, "cannot_change_owner"),
        Some(_) => {}
        None => return json_err(404, "not_member_target"),
    }
    db.prepare("UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ? AND role != 'owner'")
        .bind(&[d1_text(&body.role), d1_text(&group_id), d1_text(&body.user_id)])?
        .run()
        .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/settings — grup AYARLARINI güncelle (owner/admin; substrat
// Faz 1). body {visibility?, auto_join?, settings_json?} — KISMİ: yalnız verilen
// alanlar değişir (COALESCE). settings_json opak (sunucu yorumlamaz). 204.
// ---------------------------------------------------------------------------
#[derive(Deserialize, Default)]
struct UpdateSettingsBody {
    visibility: Option<String>,
    auto_join: Option<bool>,
    settings_json: Option<String>,
}

pub async fn update_settings(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UpdateSettingsBody = req.json().await.unwrap_or_default();
    if let Some(v) = &body.visibility {
        if !valid_visibility(v) {
            return json_err(400, "bad_visibility");
        }
    }
    let db = ctx.env.d1("DB")?;
    // Yalnız group owner/admin ayar değiştirir.
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if is_group_admin(&role) => {}
        Some(_) => return json_err(403, "forbidden"),
        None => return json_err(403, "not_member"),
    }
    // Kısmi güncelleme: COALESCE(?, mevcut) → verilmeyen alan değişmez.
    let now = now_secs() as i64;
    db.prepare(
        "UPDATE groups SET
            visibility    = COALESCE(?, visibility),
            auto_join     = COALESCE(?, auto_join),
            settings_json = COALESCE(?, settings_json),
            updated_at    = ?
         WHERE id = ?",
    )
    .bind(&[
        d1_opt_text(body.visibility.as_deref()),
        match body.auto_join {
            Some(b) => d1_int(if b { 1 } else { 0 }),
            None => d1_null(),
        },
        d1_opt_text(body.settings_json.as_deref()),
        d1_int(now),
        d1_text(&group_id),
    ])?
    .run()
    .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// DELETE /groups/:id — grubu sil (yalnız group-owner). CASCADE üyeleri siler.
// ---------------------------------------------------------------------------
pub async fn delete_group(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if role == "owner" => {}
        Some(_) => return json_err(403, "owner_required"),
        None => return json_err(403, "not_member"),
    }
    // group_members ON DELETE CASCADE ile temizlenir (FK). Güvenlik için açık DELETE de.
    db.prepare("DELETE FROM group_members WHERE group_id = ?")
        .bind(&[d1_text(&group_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM groups WHERE id = ?")
        .bind(&[d1_text(&group_id)])?
        .run()
        .await?;
    // FORWARD-SECRECY (Faz-D): server-level grup-silme = tüm üyeler çıkarıldı → epoch FLOOR++
    // (best-effort; grup silindi → log yine üye-kapısından erişilemez ama floor tutarlı kalsın).
    let _ = crate::plugin_log::bump_epoch_floor(&db, &group_id).await;
    no_content()
}
