use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

// Genesis daveti pratikte süresiz (kuruluş kapısı). ~100 yıl.
const GENESIS_TTL_SEC: u64 = 100 * 365 * 24 * 60 * 60;

/// `GET /bootstrap` — sunucu kuruluş kapısı (pre-auth, kendini-kapatan).
///
/// **Tavuk-yumurta çözümü:** invite_only sunucuda owner yaratmak için davet
/// gerekir, ama daveti üretecek owner henüz yoktur. Bu endpoint owner YOKKEN
/// otomatik bir "genesis" daveti üretir/döner; o kodu kullanan İLK kişi
/// (verify'daki ilk-kullanıcı=owner kuralı) owner olur. Owner oluşunca endpoint
/// 410 döner ve sonsuza dek kapanır → elle `OWNERTEST2026` ekleme hack'i biter,
/// sunucu kendini bootstrap'lar.
///
/// Genesis daveti **`owner_user_id IS NULL`** ile işaretlenir: gerçek davetlerin
/// (`create_invite`) hep bir üreteni vardır, genesis'in yoktur. (`email_hint`
/// işaret olarak KULLANILAMAZ — `redeem` onu kullanıcının e-postasıyla
/// eşleştirir → `email_mismatch`.) İdempotent: owner gelene kadar tekrar
/// çağrılınca aynı token döner.
///
/// **Güvenlik nüansı:** endpoint owner-yokken herkese açık → deploy ile
/// claim arası minik yarış penceresi. Kişisel/küçük/self-host'ta kabul
/// edilebilir; ileride deploy-sırrı (`ADMIN_INVITE_KEY`) ile kapı sağlamlaşır.
pub async fn bootstrap(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = ctx.env.d1("DB")?;

    // Owner zaten var mı? → kapı kapalı.
    #[derive(Deserialize)]
    struct IdRow {
        #[allow(dead_code)]
        id: String,
    }
    let owner: Option<IdRow> = db
        .prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1")
        .first(None)
        .await?;
    if owner.is_some() {
        return json_err(410, "bootstrap_complete");
    }

    // Mevcut kullanılmamış genesis daveti var mı? (owner_user_id IS NULL = sistem üretimi)
    #[derive(Deserialize)]
    struct TokenRow {
        token: String,
    }
    let existing: Option<TokenRow> = db
        .prepare(
            "SELECT token FROM invite_tokens
             WHERE used = 0 AND owner_user_id IS NULL
             ORDER BY created_at ASC LIMIT 1",
        )
        .first(None)
        .await?;

    let token = match existing {
        Some(r) => r.token,
        None => {
            // M10 (bootstrap-race): eşzamanlı iki /bootstrap çağrısı yukarıdaki
            // SELECT'i ikisi de boş görüp çoklu genesis INSERT edebiliyordu. Migration
            // 0018 partial-UNIQUE (`owner_user_id IS NULL AND used = 0`) aynı anda tek
            // kullanılmamış genesis garantiler → `INSERT OR IGNORE` yarışı kaybeden
            // çağrıda no-op (UNIQUE-violation yutulur), ardından kanonik satırı re-SELECT
            // ederek HER iki çağrı da AYNI tek token'ı döndürür (idempotent).
            let now = now_secs();
            let token = random_b64u(18); // 24 char b64u
            db.prepare(
                "INSERT OR IGNORE INTO invite_tokens (token, email_hint, used, used_by, owner_user_id, expires_at, created_at)
                 VALUES (?, NULL, 0, NULL, NULL, ?, ?)",
            )
            .bind(&[
                d1_text(&token),
                d1_int((now + GENESIS_TTL_SEC) as i64),
                d1_int(now as i64),
            ])?
            .run()
            .await?;
            // Kanonik genesis token'ı re-SELECT (INSERT OR IGNORE yarışı kaybettiyse
            // bizimki yazılmadı → yazılmış olanı oku; kazandıysak kendi token'ımız).
            let winner: Option<TokenRow> = db
                .prepare(
                    "SELECT token FROM invite_tokens
                     WHERE used = 0 AND owner_user_id IS NULL
                     ORDER BY created_at ASC LIMIT 1",
                )
                .first(None)
                .await?;
            match winner {
                Some(r) => r.token,
                None => token, // beklenmedik (index garanti) — kendi token'ımıza düş
            }
        }
    };

    Response::from_json(&serde_json::json!({
        "bootstrap_token": token,
        "note": "Bu kodu kullanan ILK kisi sunucu sahibi (owner) olur; sonra bu kapi kapanir.",
    }))
}
