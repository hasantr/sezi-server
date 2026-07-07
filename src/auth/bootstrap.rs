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

    // Owner zaten var mı? → kapı kapalı. İSTİSNA (self-heal, 2026-07-06
    // sezi-server2 vakası): owner "HAYALET" ise (kayıt yarıda ölmüş — user-satırı
    // yazıldı ama token imzası patladı, cihaz/anahtar/oturum HİÇ doğmadı) →
    // hayaleti temizle + genesis'i yeniden aç. Kullanıcı ASLA D1 konsolundan
    // DELETE çalıştırmak zorunda kalmamalı.
    #[derive(Deserialize)]
    struct OwnerRow {
        id: String,
        email: String,
        created_at: i64,
    }
    let owner: Option<OwnerRow> = db
        .prepare("SELECT id, email, created_at FROM users WHERE role = 'owner' LIMIT 1")
        .first(None)
        .await?;
    if let Some(o) = owner {
        // Hayalet-imzası (kayıt-akışı kanıtı — auth/verify.rs + devices/handlers.rs):
        //  · `devices` satırı YALNIZ auth-gerektiren PUT /devices publish'inde doğar
        //    (kayıt başarıyla token dönmeden çağrılamaz) → hayalette 0 satır.
        //  · `refresh_tokens` satırı token veren HER yolda doğar (verify/relogin/
        //    refresh-rotasyonu/device-link) → hiç giriş yapamamış hayalette 0 satır.
        //    (Aktif owner'da rotasyon hep ≥1 canlı satır bırakır; cron yalnız
        //    expired/revoked siler → aktif owner bu kapıdan GEÇMEZ, 410 aynen.)
        //  · ≥10dk yaş (grace): kayıt-akışı hâlâ sürüyor olabilir (verify döndü,
        //    cihaz-publish henüz gelmedi) → taze hesaba DOKUNMA.
        let device_count = count_rows(&db, "SELECT COUNT(*) AS n FROM devices WHERE user_id = ?", &o.id).await?;
        let refresh_count =
            count_rows(&db, "SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?", &o.id).await?;
        if !is_ghost_owner(device_count, refresh_count, o.created_at, now_secs()) {
            return json_err(410, "bootstrap_complete");
        }
        // GÜVENLİK NOTU: cihazsız+oturumsuz owner zaten HİÇBİR ŞEY yapamaz —
        // anahtarı yok (mesaj çözemez/atamaz), token'ı yok (hiçbir endpoint'e
        // giremez). Bu geri-kazanım meşru bir sahipten bir şey ÇALMAZ; yalnız
        // ölü owner-yuvasını açar. Kalıntı-kenar: 30+ gün hiç bağlanmamış VE
        // cihaz-listesi hiç yayınlamamış (device-list öncesi legacy) bir gerçek
        // owner teorik olarak kriterle örtüşür — güncel istemciler kayıtta cihaz
        // yayınladığı için pratikte boş küme; kabul edilen ödün (yorumla kayıtlı).
        console_warn!(
            "bootstrap: HAYALET-owner tespit edildi (id={}, devices=0, refresh=0, yas>=grace) → temizlenip genesis yeniden aciliyor (self-heal; 2026-07-06 sezi-server2 vakasi)",
            o.id
        );
        // Temizlik TEK ATOMİK BATCH (D1 batch = implicit transaction) → yarım-
        // temizlik diye yeni bir bozuk-durum sınıfı doğamaz. FK sırası admin
        // remove_member deseninin aynısı (admin/handlers.rs): önce referans veren
        // satırlar, en son users. groups.created_by kasıtlı YOK: hayalet grup
        // kuramaz (auth ister); imkânsız-satır varsa FK batch'i geri sarar =
        // güvenli başarısızlık (hiçbir şey silinmez, 500). Not: hayaletin grup-
        // anahtarı hiç olmadığından epoch-floor bump'ı da gereksiz.
        db.batch(vec![
            db.prepare("UPDATE invite_tokens SET used_by = NULL WHERE used_by = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("UPDATE invite_tokens SET owner_user_id = NULL WHERE owner_user_id = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM signed_prekeys WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM pending_messages WHERE recipient_id = ? OR sender_id = ?")
                .bind(&[d1_text(&o.id), d1_text(&o.id)])?,
            db.prepare("DELETE FROM media_objects WHERE uploader_id = ?")
                .bind(&[d1_text(&o.id)])?,
            // refresh/devices kriter gereği zaten 0 satır — savunmacı (batch ucuz).
            db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM push_tokens WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM group_members WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM devices WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM device_lists WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            // Hayaletin e-postasına takılı kod artığı (normalde verify silmişti;
            // savunmacı) — e-posta UNIQUE olduğundan yeni kayıt da bu adresle
            // yeniden yapılabilir hâle gelir.
            db.prepare("DELETE FROM verification_codes WHERE email = ?")
                .bind(&[d1_text(&o.email)])?,
            db.prepare("DELETE FROM users WHERE id = ? AND role = 'owner'")
                .bind(&[d1_text(&o.id)])?,
        ])
        .await?;
        console_log!("bootstrap: hayalet-owner {} temizlendi; genesis akisina donuluyor", o.id);
        // Düş: aşağıdaki normal genesis-üretim akışı (kullanılmış eski genesis
        // used=1 olduğundan seçilmez → taze token üretilir).
    }

    let token = ensure_genesis_token(&db).await?;

    Response::from_json(&serde_json::json!({
        "bootstrap_token": token,
        "note": "Bu kodu kullanan ILK kisi sunucu sahibi (owner) olur; sonra bu kapi kapanir.",
    }))
}

/// Genesis token get-or-mint (bootstrap handler + hoş-geldin sayfası ortak yolu).
/// SÖZLEŞME: yalnız owner-YOK durumunda çağrılmalı (çağıran kapıyı kontrol eder);
/// kendisi owner denetimi YAPMAZ. Davranış `bootstrap()`ın orijinal gövdesiyle
/// bit-aynı: mevcut kullanılmamış genesis'i SELECT → yoksa INSERT-OR-IGNORE +
/// kanonik re-SELECT (M10 yarış-deseni AYNEN korunur).
pub(crate) async fn ensure_genesis_token(db: &D1Database) -> Result<String> {
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
    Ok(token)
}

/// Hayalet-owner grace penceresi: hesap bundan gençse ASLA hayalet sayılmaz
/// (kayıt-akışı sürüyor olabilir: verify döndü, cihaz-publish yolda).
const GHOST_GRACE_SEC: i64 = 10 * 60;

/// Hayalet-owner kriteri (SAF → unit-testli). Konservatif VE-zinciri:
/// cihaz-satırı YOK + refresh-token-satırı YOK + hesap ≥10dk eski.
/// Üçü birden sağlanmazsa owner'a DOKUNULMAZ (410 aynen).
fn is_ghost_owner(device_count: i64, refresh_count: i64, created_at: i64, now: u64) -> bool {
    let age = (now as i64).saturating_sub(created_at); // saat-kayması → negatif yaş = genç say
    device_count == 0 && refresh_count == 0 && age >= GHOST_GRACE_SEC
}

/// `SELECT COUNT(*) AS n ...` yardımcısı (tek-kolonlu sayım).
async fn count_rows(db: &D1Database, sql: &str, user_id: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    let row: Option<CountRow> = db.prepare(sql).bind(&[d1_text(user_id)])?.first(None).await?;
    Ok(row.map(|r| r.n).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_750_000_000; // hesap oluşturma anı (sn)

    /// Saha-vakası profili (2026-07-06 sezi-server2): cihazsız + oturumsuz +
    /// grace'i geçmiş owner → hayalet (geri-kazanım açılır).
    #[test]
    fn hayalet_profili_taniniyor() {
        let now = (T0 + GHOST_GRACE_SEC) as u64; // tam sınır: age == grace → hayalet
        assert!(is_ghost_owner(0, 0, T0, now));
        assert!(is_ghost_owner(0, 0, T0, now + 86_400)); // günler sonra da
    }

    /// Konservatiflik: TEK bir canlılık sinyali bile varsa DOKUNULMAZ.
    #[test]
    fn cihazli_veya_oturumlu_owner_asla_hayalet_degil() {
        let now = (T0 + 30 * 24 * 3600) as u64; // 30 gün sonra bile
        assert!(!is_ghost_owner(1, 0, T0, now)); // cihaz yayınlamış
        assert!(!is_ghost_owner(0, 1, T0, now)); // refresh-token'ı var
        assert!(!is_ghost_owner(2, 3, T0, now)); // ikisi de var
    }

    /// Grace: taze hesap (kayıt-akışı sürüyor olabilir) hayalet sayılmaz.
    #[test]
    fn taze_hesap_grace_icinde_korunur() {
        assert!(!is_ghost_owner(0, 0, T0, T0 as u64)); // aynı an
        assert!(!is_ghost_owner(0, 0, T0, (T0 + GHOST_GRACE_SEC - 1) as u64)); // sınırın 1sn altı
    }

    /// Saat-kayması savunması: created_at gelecekte görünürse (negatif yaş) genç say.
    #[test]
    fn gelecek_tarihli_hesap_hayalet_degil() {
        assert!(!is_ghost_owner(0, 0, T0 + 3600, T0 as u64));
    }
}
