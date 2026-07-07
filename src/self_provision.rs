//! Self-provisioning — self-host Faz A (zero-CLI deploy ön-koşulu).
//!
//! Hedef: worker'ı GitHub'dan fork'layıp Deploy-to-Cloudflare ile KENDİ CF
//! hesabına kuran kullanıcı, `wrangler secret put` ve `wrangler d1 migrations
//! apply` BİLMEDEN çalışan bir server alsın. İki bacak:
//!
//! **A1 — Anahtar self-provisioning** (`JWT_SIGNING_KEY` + `ADMIN_INVITE_KEY`):
//! env-first / D1-fallback / yoksa-ÜRET-persist (cf_analytics `resolve_cfg`
//! deseninin kalıcı-anahtar varyantı):
//!   1. env secret varsa → o kullanılır (bugünkü davranış BİT-AYNI; env-set
//!      HER ZAMAN kazanır — güvenlik-bilinçli owner anahtarı secret'a taşıyabilir).
//!      Bu yolda D1'e HİÇ gidilmez, memoize da gerekmez (env okuma sync+ucuz).
//!   2. Yoksa D1 `server_config` (0025) okunur → izolate-scope cache'e alınır
//!      (JWT anahtarı HER istekte okunur = hot-path; D1-roundtrip'i her isteğe
//!      SOKMAMAK için thread_local memoize — WASM izolate'i tek-thread).
//!   3. O da yoksa (taze fork ilk boot) ÜRETİLİR + D1'e persist edilir.
//!      Yarış guard'ı: `ON CONFLICT DO NOTHING` + persist-sonrası re-SELECT →
//!      eşzamanlı iki cold-start ASLA farklı anahtar kullanmaz (D1 tek gerçek).
//!
//! GÜVENLİK NOTU: anahtar D1-at-rest durur (CF disk-şifreli) — self-host
//! dürüst-server modeli. Anahtar HİÇBİR endpoint'te dönmez (yalnız worker-içi).
//!
//! **A2 — D1 self-migration**: `migrations/*.sql` gömülü (`include_str!`);
//! ilk istekte `_sezi_migrations` tracking'ine göre eksikler TEK `db.batch`te
//! uygulanır (2026-07-06 free-plan vakası: Workers free-planı istek-başına
//! ~50 subrequest kapıyor; eski dosya-başına batch+track-INSERT deseni taze
//! kurulum ilk-boot'unda ~50+ D1-çağrısıyla ortadan kesiliyordu → jwks/verify
//! deterministik 500. Tek-batch ilk-boot'u ~4 D1-çağrısına indirir + tüm
//! bekleyenler hepsi-ya-hiç atomik olur).
//! wrangler-uyumu (KRİTİK): mevcut prod migration'ları `wrangler d1 migrations
//! apply` ile uyguladı → wrangler'ın kendi `d1_migrations` tablosundaki kayıtlar
//! uygulanmış-SAYILIR (prod'da hiçbir migration yeniden koşmaz). Ek kemer:
//! benign şema-çakışması ("duplicate column name"/"already exists") →
//! tolerant-apply (aşağıda `apply_one`). CLI yolu çalışmaya devam eder
//! (`wrangler.toml migrations_dir` KALDI; self-migration ek güvence).

use std::cell::{Cell, RefCell};
use std::collections::HashSet;

use worker::*;

use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

// ── Gömülü migration listesi ────────────────────────────────────────────────
// SIRALI + ELLE BAKIMLI (build-script yerine bilinçli sade çözüm): yeni bir
// migrations/NNNN_*.sql eklendiğinde buraya da satır eklenmeli. Unit test
// `migrations_listesi_klasorle_senkron` unutmayı derleme-sonrası yakalar
// (cargo test klasörü okuyup listeyle karşılaştırır).
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../migrations/0001_init.sql")),
    ("0002_push_tokens", include_str!("../migrations/0002_push_tokens.sql")),
    (
        "0003_admin_and_settings",
        include_str!("../migrations/0003_admin_and_settings.sql"),
    ),
    (
        "0004_owner_and_invite_tracking",
        include_str!("../migrations/0004_owner_and_invite_tracking.sql"),
    ),
    ("0005_retention", include_str!("../migrations/0005_retention.sql")),
    ("0006_groups", include_str!("../migrations/0006_groups.sql")),
    (
        "0007_group_settings",
        include_str!("../migrations/0007_group_settings.sql"),
    ),
    (
        "0008_group_join_consent",
        include_str!("../migrations/0008_group_join_consent.sql"),
    ),
    ("0009_turn_usage", include_str!("../migrations/0009_turn_usage.sql")),
    (
        "0010_message_retention",
        include_str!("../migrations/0010_message_retention.sql"),
    ),
    ("0011_devices", include_str!("../migrations/0011_devices.sql")),
    (
        "0012_device_addressing_s1",
        include_str!("../migrations/0012_device_addressing_s1.sql"),
    ),
    (
        "0013_device_otk_cut",
        include_str!("../migrations/0013_device_otk_cut.sql"),
    ),
    ("0014_device_link", include_str!("../migrations/0014_device_link.sql")),
    (
        "0015_signed_prekeys_device_pk",
        include_str!("../migrations/0015_signed_prekeys_device_pk.sql"),
    ),
    (
        "0016_otk_device_unique",
        include_str!("../migrations/0016_otk_device_unique.sql"),
    ),
    (
        "0017_device_list_highwater",
        include_str!("../migrations/0017_device_list_highwater.sql"),
    ),
    ("0018_one_owner", include_str!("../migrations/0018_one_owner.sql")),
    (
        "0019_plugin_epoch_floor",
        include_str!("../migrations/0019_plugin_epoch_floor.sql"),
    ),
    (
        "0020_push_wake_debounce",
        include_str!("../migrations/0020_push_wake_debounce.sql"),
    ),
    ("0021_fanout_retry", include_str!("../migrations/0021_fanout_retry.sql")),
    ("0022_quotas", include_str!("../migrations/0022_quotas.sql")),
    ("0023_quota_caps", include_str!("../migrations/0023_quota_caps.sql")),
    ("0024_cf_config", include_str!("../migrations/0024_cf_config.sql")),
    (
        "0025_server_config",
        include_str!("../migrations/0025_server_config.sql"),
    ),
];

thread_local! {
    /// İzolate-scope "migration'lar kontrol edildi" bayrağı — her istekte D1'e
    /// gitmemek için (WASM izolate'i tek-thread → thread_local = izolate-memoize).
    static MIGRATIONS_CHECKED: Cell<bool> = const { Cell::new(false) };
    /// D1'den çözülen/üretilen JWT PKCS8-PEM (YALNIZ env-secret yokken dolar;
    /// jwt.rs `load_signing_key` fallback'i buradan okur — hot-path D1'siz).
    static JWT_PEM: RefCell<Option<String>> = const { RefCell::new(None) };
    /// D1'den çözülen/üretilen admin-invite anahtarı (b64url 32B).
    static ADMIN_INVITE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Boot-guard — `#[event(fetch)]` ve `#[event(scheduled)]` girişinde çağrılır.
/// İzolate-scope memoized: ilk çağrı işi yapar, sonrakiler no-op. env-secret'lı
/// + wrangler-migrated kurulumda (bizim prod) TAMAMEN no-op'a düşer.
pub async fn ensure_ready(env: &Env) {
    // ANAHTAR ÖNCE, MİGRATION SONRA (2026-07-07 free-plan vakası): free CF
    // hesabında istek-başı subrequest bütçesi dar; anahtar-yolu ağır
    // 25-migration-batch'iyle AYNI istekte yarışınca aç kalıp jwks/verify 500
    // veriyordu (migration'lar tabloları kurar → bootstrap/welcome çalışır ama
    // anahtar üretilemez). ensure_keys kendi `server_config` tablosunu kurar
    // (migration 0025'e bağımlı DEĞİL) → birkaç subrequest'te BİTER; migration'lar
    // sonra koşar, bütçeyi tüketse bile anahtar zaten hazırdır.
    ensure_keys(env).await;
    ensure_migrations(env).await;
}

/// Yalnız anahtar bacağı — UserInbox DO'su (`ws_upgrade` token doğrulaması)
/// için: DO fetch'i lib.rs `#[event(fetch)]`'ten GEÇMEZ → kendi izolate'inin
/// cache'ini doldurmalı. Memoized; env-secret varsa D1'e hiç gitmez.
pub async fn ensure_keys(env: &Env) {
    ensure_one_key(
        env,
        "JWT_SIGNING_KEY",
        "jwt_signing_key",
        &JWT_PEM,
        generate_jwt_signing_pem,
        validate_jwt_pem,
    )
    .await;
    ensure_one_key(
        env,
        "ADMIN_INVITE_KEY",
        "admin_invite_key",
        &ADMIN_INVITE,
        generate_admin_invite_key,
        validate_invite_key,
    )
    .await;
}

/// jwt.rs `load_signing_key` fallback'i: boot'ta D1'den çözülen/üretilen PEM.
/// env-secret varken HİÇ dolmaz (env yolu jwt.rs'te doğrudan, bugünkü gibi).
pub fn cached_jwt_pem() -> Option<String> {
    JWT_PEM.with(|c| c.borrow().clone())
}

/// ADMIN_INVITE_KEY çözümü — env-first, sonra self-provision cache.
/// NOT: bugün (2026-07) bu anahtarı kod HİÇBİR yerde okumuyor (wrangler.toml'da
/// dokümante, bootstrap.rs'te "ileride kapı sertleştirme" notu). Self-provision
/// onu taze fork'ta da ÜRETİP hazır tutar; gelecekteki tüketici (bootstrap
/// kapısı) bu fonksiyonu çağırır.
#[allow(dead_code)]
pub fn resolve_admin_invite_key(env: &Env) -> Option<String> {
    if let Ok(s) = env.secret("ADMIN_INVITE_KEY") {
        return Some(s.to_string());
    }
    ADMIN_INVITE.with(|c| c.borrow().clone())
}

// ── A1: anahtar çözüm zinciri ───────────────────────────────────────────────

async fn ensure_one_key(
    env: &Env,
    env_name: &str,
    db_key: &str,
    cache: &'static std::thread::LocalKey<RefCell<Option<String>>>,
    generate: fn() -> Result<String>,
    validate: fn(&str) -> bool,
) {
    // 1) env secret → YALNIZ boş-değil VE validate geçerse kabul (D1'e gitme).
    //    KRİTİK (2026-07-07 free-hesap vakası): buton-deploy runtime'ında (yeni
    //    wrangler) KURULMAMIŞ secret `Ok("")` dönebiliyor (eski runtime `Err`);
    //    `is_ok()` görünce boş/bozuk değer env-first dalına girip self-heal'i
    //    ATLATIYORDU → jwks/verify "PEM type label invalid" 500. Artık boş/geçersiz
    //    env-secret YOK SAYILIR → self-provision (D1/üretim) devreye girer.
    //    (Geçerli env-secret'lı prod bit-aynı: non-empty+validate → erken dönüş.)
    if let Ok(s) = env.secret(env_name) {
        let v = s.to_string();
        if !v.trim().is_empty() && validate(&v) {
            return;
        }
    }
    // 2) İzolate cache dolu → tamam (hot-path D1-roundtrip'siz).
    if cache.with(|c| c.borrow().is_some()) {
        return;
    }
    // 3) D1'den oku (+VALIDATE; bozuksa yeniden-üret = self-heal) / 4) yoksa
    //    üret+persist. Hata = console_error + cache boş kalır → SONRAKİ istek
    //    yeniden dener (D1 geçici hatasında self-heal; bu yol zaten yalnız
    //    env-secret'sız kurulumlarda çalışır).
    match resolve_from_db(env, db_key, generate, validate).await {
        Ok(v) => cache.with(|c| *c.borrow_mut() = Some(v)),
        Err(e) => console_error!("self_provision: {} cozulemedi: {}", db_key, e),
    }
}

/// D1 `server_config` oku + DOĞRULA; bozuksa/yoksa üret + persist.
///
/// SELF-HEAL (2026-07-06 sezi-server2 vakası): eski/bozuk bir build D1'e
/// GEÇERSİZ JWT-PEM yazmıştı → güncel kod onu körü körüne kullanıp her token
/// imzasında/jwks'te 500 veriyordu (kayıt yarıda öldü → hayalet-owner →
/// sunucu kalıcı-kilit). Kural: kullanıcı ASLA worker-içini elle temizlemez →
/// D1'den okunan değer validate'i GEÇMEZSE yeniden üret + ÜSTÜNE yaz.
async fn resolve_from_db(
    env: &Env,
    db_key: &str,
    generate: fn() -> Result<String>,
    validate: fn(&str) -> bool,
) -> Result<String> {
    let db = env.d1("DB")?;
    // server_config'i anahtar-yolu KENDİSİ kurar (migration 0025'ten bağımsız)
    // → ensure_keys migration'lardan ÖNCE koşabilir (bkz. ensure_ready sıra
    // gerekçesi). IF NOT EXISTS → migration 0025 sonra koşarsa no-op.
    db.prepare(
        "CREATE TABLE IF NOT EXISTS server_config \
         (key TEXT PRIMARY KEY, value TEXT NOT NULL, created_at INTEGER NOT NULL)",
    )
    .run()
    .await?;
    if let Some(v) = read_config(&db, db_key).await? {
        if validate(&v) {
            return Ok(v);
        }
        // Bozuk kayıt → yeniden üret + INSERT OR REPLACE (bilinçli: ON CONFLICT
        // DO NOTHING bozuk kaydı KORURDU; burada üstüne yazmak ŞART).
        console_warn!(
            "self_provision: {} D1 kaydi BOZUK (validate gecmedi) → yeniden uretiliyor (self-heal; 2026-07-06 sezi-server2 vakasi)",
            db_key
        );
        let candidate = generate()?;
        // Paranoya: ürettiğimizi de yazmadan önce doğrula — üretici ile
        // doğrulayıcı ayrışırsa bozuk değeri D1'e persist etmeyelim.
        if !validate(&candidate) {
            return Err(Error::RustError(format!(
                "self_provision: {db_key} uretilen deger validate'i gecemedi (uretici/dogrulayici uyumsuz?)"
            )));
        }
        db.prepare(
            "INSERT OR REPLACE INTO server_config (key, value, created_at) VALUES (?, ?, ?)",
        )
        .bind(&[d1_text(db_key), d1_text(&candidate), d1_int(now_secs() as i64)])?
        .run()
        .await?;
        console_log!(
            "self_provision: {} yeniden uretildi + D1'e yazildi (bozuk kaydin ustune)",
            db_key
        );
        // Yarış notu: iki izolate aynı anda self-heal ederse REPLACE'te
        // son-yazan kazanır. İki değer de TAZE-ÜRETİM + validate'li olduğu
        // için zararsız: kaybeden izolate kendi değerini kullanır, izolate
        // recycle'ında herkes D1'deki kazanana yakınsar (bozuk-kayıt tekrar
        // doğamaz — yazılan her değer validate'ten geçti).
        return Ok(candidate);
    }

    // Taze fork ilk boot: ÜRET + persist. YARIŞ GUARD'ı: iki eşzamanlı
    // cold-start aynı anda üretebilir → `ON CONFLICT DO NOTHING` (ilk yazan
    // kazanır, kaybeden no-op) + persist-SONRASI re-SELECT ile kazanan değer
    // geri okunur → iki instance ASLA farklı anahtar kullanmaz (son kullanılan
    // = D1'deki tek gerçek).
    let candidate = generate()?;
    // Paranoya (yukarıdakiyle aynı gerekçe): bozuk değer D1'e persist edilmesin.
    if !validate(&candidate) {
        return Err(Error::RustError(format!(
            "self_provision: {db_key} uretilen deger validate'i gecemedi (uretici/dogrulayici uyumsuz?)"
        )));
    }
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO NOTHING",
    )
    .bind(&[d1_text(db_key), d1_text(&candidate), d1_int(now_secs() as i64)])?
    .run()
    .await?;
    console_log!(
        "self_provision: {} uretildi + D1'e persist edildi (taze kurulum)",
        db_key
    );
    match read_config(&db, db_key).await? {
        // Kazanan da validate'ten geçmeli: yarışı eski/bozuk bir yazar
        // kazandıysa (teorik) onu kullanma → kendi taze değerimize düş;
        // sonraki boot'un bozuk-kayıt dalı D1'i onarır.
        Some(winner) if validate(&winner) => Ok(winner),
        Some(_) => {
            console_warn!(
                "self_provision: {} yarisi kazanan D1 degeri BOZUK — kendi taze degerimiz kullaniliyor (sonraki boot self-heal eder)",
                db_key
            );
            Ok(candidate)
        }
        // Beklenmedik (insert az önce başarılıydı) — kendi değerimize düş.
        None => Ok(candidate),
    }
}

// ── Anahtar doğrulayıcıları (saf → unit-testli) ─────────────────────────────

/// D1'den okunan JWT-PEM geçerli mi? jwt.rs'in KULLANACAĞI parser'ın kendisiyle
/// doğrulanır (`parse_signing_pem`) → "validate geçti ama imzada patladı"
/// ayrışması imkânsız (aynı fonksiyon).
fn validate_jwt_pem(v: &str) -> bool {
    crate::auth::jwt::parse_signing_pem(v).is_ok()
}

/// Admin-invite anahtarı için makul kapı: boş/whitespace olmasın yeter
/// (opak paylaşılan-sır; format zorunluluğu yok).
fn validate_invite_key(v: &str) -> bool {
    !v.trim().is_empty()
}

async fn read_config(db: &D1Database, key: &str) -> Result<Option<String>> {
    #[derive(serde::Deserialize)]
    struct Row {
        value: String,
    }
    let row: Option<Row> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[d1_text(key)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.value))
}

/// Ed25519 JWT imza anahtarı üret — jwt.rs doğrulayıcısıyla AYNI crate
/// (ed25519-dalek) + AYNI format (PKCS8 PEM; `from_pkcs8_pem` roundtrip'i
/// unit-testli). `LineEnding::LF` → gerçek newline'lı PEM: jwt.rs'in env-secret
/// için yaptığı `"\\n"→"\n"` replace'i bu değerde no-op kalır.
fn generate_jwt_signing_pem() -> Result<String> {
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| Error::RustError(format!("self_provision: rng: {e}")))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::RustError(format!("self_provision: pkcs8 pem encode: {e}")))?;
    Ok(pem.to_string())
}

/// ADMIN_INVITE_KEY üret: 32-byte CSPRNG → base64url (padding'siz, 43 char).
/// worker'da RNG = getrandom (js feature; utils.rs `random_b64u` aynı yol).
fn generate_admin_invite_key() -> Result<String> {
    Ok(crate::utils::random_b64u(32))
}

// ── A2: self-migration ──────────────────────────────────────────────────────

async fn ensure_migrations(env: &Env) {
    if MIGRATIONS_CHECKED.with(|c| c.get()) {
        return;
    }
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(e) => {
            console_error!("self_provision: D1 binding yok: {}", e);
            return;
        }
    };
    // FAIL-SOFT (fail-open DEĞİL ama 500 de değil): migration başarısızsa
    // istekleri 500'lemek yerine MEVCUT şema ile hizmete devam. Gerekçe:
    // migration'lar batch-atomik (yarım-şema yok) → başarısızlık = şema eski
    // kaldı; eski şemayla çalışan endpoint'ler çalışmaya devam eder, yenisini
    // isteyenler zaten anlamlı hata verir. Tam-blokaj self-host operatörüne
    // "server ölü" görünürdü; böyle yalnız yeni özellik aksar + log konuşur.
    //
    // Bayrak YALNIZ BAŞARIDA set edilir (2026-07-06 free-plan vakası): eski
    // "denemeden önce set" kararı, subrequest-limitinde ortadan kesilen bir
    // ilk-boot'u izolat ömrü boyunca ZEHİRLİ bırakıyordu (migration'lar hiç
    // bitmedi ama bir daha denenmedi → deterministik jwks/verify 500). Yeni
    // kural: Err'de set ETME → sonraki istek yeniden dener (migration'lar
    // tolerant + batch-atomik = tekrar-GÜVENLİ). Kalıcı-hata döngüsü riski,
    // kesik-boot'ta kalıcı-zehirden iyidir; batch başarılıysa zaten tek-sefer.
    match run_migrations(&db).await {
        Ok(()) => MIGRATIONS_CHECKED.with(|c| c.set(true)),
        Err(e) => console_error!(
            "self_provision: self-migration durdu (mevcut sema ile hizmete devam): {}",
            e
        ),
    }
}

async fn run_migrations(db: &D1Database) -> Result<()> {
    // Tracking tablosu — wrangler'ın `d1_migrations`'ından BİLİNÇLİ ayrı isim:
    // wrangler kendi tablosunu sahiplenir/şemasını değiştirebilir; karışmayız.
    db.prepare(
        "CREATE TABLE IF NOT EXISTS _sezi_migrations \
         (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
    )
    .run()
    .await?;

    #[derive(serde::Deserialize)]
    struct NameRow {
        name: String,
    }

    let mut applied: HashSet<String> = db
        .prepare("SELECT name FROM _sezi_migrations")
        .all()
        .await?
        .results::<NameRow>()?
        .into_iter()
        .map(|r| r.name)
        .collect();

    // wrangler-uyumu (KRİTİK): bizim prod migration'ları `wrangler d1 migrations
    // apply` ile uyguladı; wrangler bunları kendi `d1_migrations` tablosunda
    // tutar (name = "0001_init.sql" biçiminde). O kayıtları uygulanmış-SAY →
    // prod'da ilk self-migration HİÇBİR migration'ı yeniden koşmaz (deploy
    // no-op). FAIL-OPEN: tablo yok (taze fork, hiç wrangler görmemiş DB) →
    // yok say. Her izolate-boot'ta merge edilir (ucuz tek SELECT): ileride
    // biri CLI ile 0026 uygularsa self-migration onu da uygulanmış görür.
    if let Ok(res) = db.prepare("SELECT name FROM d1_migrations").all().await {
        if let Ok(rows) = res.results::<NameRow>() {
            for r in rows {
                applied.insert(normalize_migration_name(&r.name).to_string());
            }
        }
    }

    let pending: Vec<(&str, &str)> = MIGRATIONS
        .iter()
        .filter(|(name, _)| !applied.contains(*name))
        .copied()
        .collect();
    // Prod bit-aynı guard: wrangler-seed'li kurulumda bekleyen = 0 → tek-batch
    // HİÇ kurulmaz (erken dönüş; bugünkü prod deploy no-op davranışı korunur).
    if pending.is_empty() {
        return Ok(());
    }

    // TEK-BATCH (2026-07-06 free-plan subrequest bütçesi): bekleyen TÜM
    // dosyaların statement'ları + her dosyanın tracking-INSERT'i dosya-sırasında
    // tek `db.batch`e (= tek subrequest, implicit transaction) girer. Eski
    // dosya-başına batch+INSERT deseni taze kurulumda ~50 D1-çağrısıydı →
    // Workers free-planının ~50-subrequest kapısında ilk-boot ortadan
    // kesiliyordu. Atomiklik de GÜÇLENDİ: 0017-tipi tuzak ("çıplak ALTER +
    // ardıl UPDATE") artık yalnız dosya-içi değil, TÜM bekleyen küme için
    // hepsi-ya-hiç — kesik/yarım şema durumu imkânsız.
    let merged = merge_pending_statements(&pending);
    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(merged.len());
    for m in &merged {
        match m {
            MergedStmt::Sql(s) => stmts.push(db.prepare(s)),
            MergedStmt::Track(name) => stmts.push(
                db.prepare(
                    "INSERT OR IGNORE INTO _sezi_migrations (name, applied_at) VALUES (?, ?)",
                )
                .bind(&[d1_text(name), d1_int(now_secs() as i64)])?,
            ),
        }
    }
    match db.batch(stmts).await {
        Ok(_) => {
            console_log!(
                "self_provision: {} migration tek-batch uygulandi",
                pending.len()
            );
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if is_benign_schema_conflict(&msg) {
                // Şema-çakışması (duplicate-column / already-exists): iki
                // eşzamanlı cold-start yarışı ya da "wrangler-uygulanmış ama
                // d1_migrations tablosuna erişilemedi" DB'si. Tek-batch geri
                // sarıldı (şemaya dokunulmadı) → DOSYA-DOSYA tolerant-apply
                // fallback'ine düş: çakışan dosyalar uygulanmış-sayılır,
                // gerçekten eksikler koşar. NADİR yol — subrequest maliyeti
                // eski desenle aynı (dosya-başına ≤2 çağrı), kabul edildi.
                console_warn!(
                    "self_provision: tek-batch sema-cakismasi ({}) → dosya-dosya tolerant fallback",
                    msg
                );
                for &(name, sql) in &pending {
                    apply_one(db, name, sql).await?;
                }
                Ok(())
            } else {
                // GERÇEK hata. Tek-batch'te "hangi dosya patladı" bilgisi yok →
                // D1'in ham hata metnini aynen taşı (SQLite mesajı çoğu kez
                // tablo/kolon adıyla dosyayı ele verir); dosya-bazlı teşhis
                // gerekirse fallback yolu zaten dosya-adıyla raporlar.
                Err(Error::RustError(format!(
                    "tek-batch migration ({} bekleyen): {msg}",
                    pending.len()
                )))
            }
        }
    }
}

/// Tek migration'ı ATOMİK uygula — artık YALNIZ tek-batch'in benign
/// şema-çakışması fallback'inde çağrılır (ana yol = `run_migrations` tek-batch;
/// bu yol dosya-bazlı tolerant-apply gerektiğinde devreye girer). D1 batch =
/// implicit transaction: bir statement bile hata verirse TAMAMI rollback —
/// devices/handlers.rs deseninin aynısı. Atomiklik 0017-tipi tuzağı dosya-içi
/// kapatır: "çıplak ALTER (duplicate column) + ardıl UPDATE" dosyasında ALTER
/// hatası TÜM batch'i geri sarar → UPDATE tek başına ASLA koşmaz (koşsaydı
/// canlı `device_list_rev` high-water'ını geri çekerdi = veri regresyonu;
/// 2026-07-06 migration-denetim bulgusu). Tek-batch ana yolu bunu daha da
/// güçlendirir: hepsi-ya-hiç TÜM bekleyen küme için geçerli.
async fn apply_one(db: &D1Database, name: &str, sql: &str) -> Result<()> {
    let statements = split_sql_statements(sql);
    if statements.is_empty() {
        // Savunmacı: boş/yorum-only dosya → uygulanmış say (koşacak şey yok).
        return record_applied(db, name).await;
    }
    let stmts: Vec<D1PreparedStatement> = statements.iter().map(|s| db.prepare(s)).collect();
    match db.batch(stmts).await {
        Ok(_) => {
            record_applied(db, name).await?;
            console_log!("self_provision: migration uygulandi: {}", name);
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if is_benign_schema_conflict(&msg) {
                // TOLERANT-APPLY: "duplicate column name" / "already exists" =
                // şema bu migration'ı ZATEN içeriyor (wrangler-uygulanmış ama
                // d1_migrations kaydına erişilemeyen DB, ya da iki eşzamanlı
                // cold-start'ın migration yarışında kaybeden taraf). Batch geri
                // sarıldı → mevcut şemaya DOKUNULMADI; uygulanmış-say + devam.
                // (0001..0024 dökümü: idempotent-olmayan tek sınıf çıplak
                // ALTER ADD COLUMN + 0014'ün IF-NOT-EXISTS'siz CREATE'i; ikisi
                // de yalnız bu iki mesajı üretir.)
                console_warn!(
                    "self_provision: migration zaten-uygulanmis sayildi ({}): {}",
                    name,
                    msg
                );
                record_applied(db, name).await
            } else {
                // GERÇEK hata: kaydetme + zinciri DURDUR (sonraki migration'lar
                // buna bağımlı olabilir). Çağıran fail-soft davranır; sonraki
                // izolate boot yeniden dener.
                Err(Error::RustError(format!("migration {name}: {msg}")))
            }
        }
    }
}

async fn record_applied(db: &D1Database, name: &str) -> Result<()> {
    db.prepare("INSERT OR IGNORE INTO _sezi_migrations (name, applied_at) VALUES (?, ?)")
        .bind(&[d1_text(name), d1_int(now_secs() as i64)])?
        .run()
        .await?;
    Ok(())
}

// ── Saf yardımcılar (unit-testli) ───────────────────────────────────────────

/// Tek-batch birleştirmesinin bir öğesi: migration dosyasından ham SQL
/// statement ya da o dosyanın `_sezi_migrations` tracking-INSERT işareti
/// (INSERT'in kendisi bind'li — SQL metni çağıranda kurulur; burada yalnız
/// dosya adı taşınır ki birleştirme SAF + unit-testli kalsın).
#[derive(Debug, PartialEq)]
enum MergedStmt {
    Sql(String),
    Track(String),
}

/// Bekleyen dosyaları TEK batch vektörüne birleştir — sıra sözleşmesi:
/// dosya1-stmt'leri, dosya1-track, dosya2-stmt'leri, dosya2-track, ...
/// (track her zaman kendi dosyasının statement'larından SONRA: batch implicit
/// transaction olsa da sıra, fallback teşhisi ve okunabilirlik için korunur).
/// Boş/yorum-only dosya → yalnız track (apply_one'ın "uygulanmış say"
/// savunmasıyla aynı sonuç). Boş bekleyen → boş vektör.
fn merge_pending_statements(pending: &[(&str, &str)]) -> Vec<MergedStmt> {
    let mut out = Vec::new();
    for &(name, sql) in pending {
        for s in split_sql_statements(sql) {
            out.push(MergedStmt::Sql(s));
        }
        out.push(MergedStmt::Track(name.to_string()));
    }
    out
}

/// wrangler `d1_migrations.name` = dosya adı (".sql" uzantılı) — bizim liste
/// uzantısız. Normalize: trim + ".sql" soy.
fn normalize_migration_name(raw: &str) -> &str {
    let t = raw.trim();
    t.strip_suffix(".sql").unwrap_or(t)
}

/// SQL dosyasını statement'lara böl. NAİF `;`-split DEĞİL: migration
/// yorumlarının İÇİNDE `;` geçiyor (gerçek örnek: 0014 inline yorumu
/// "... consume = satır DELETE; 'consumed' persist EDİLMEZ") — naif split
/// CREATE TABLE'ı ortadan keserdi. Küçük state-machine: string-literal
/// (`''` escape dahil) + `--` satır-yorumu + `/* */` blok-yorumu farkında;
/// yorumlar ÇIKARILIR (D1 prepare'ine saf SQL gider), `;` yalnız normal
/// bağlamda statement sonlandırır. Trigger (BEGIN...END içinde `;`) migration
/// dosyalarında YOK — eklenirse bu splitter yetmez, o gün yeniden ele alınır.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            cur.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    // '' = escape'li tek-tırnak → string devam ediyor.
                    cur.push(chars.next().unwrap());
                } else {
                    in_string = false;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                cur.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                // Satır-yorumu: satır sonuna kadar at; newline koru (token
                // bitişikliği bozulmasın).
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                cur.push('\n');
            }
            '/' if chars.peek() == Some(&'*') => {
                // Blok-yorum: `*/`e kadar at (bugünkü dosyalarda yok; savunmacı).
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                cur.push(' ');
            }
            ';' => {
                let stmt = cur.trim();
                if !stmt.is_empty() {
                    out.push(stmt.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Tolerant-apply sınıflandırması: YALNIZ "şema zaten böyle" hataları benign.
/// SQLite mesajları: "duplicate column name: X" (çıplak ALTER ADD COLUMN
/// re-run — 0003/0004/0005/0007/0008/0010/0012/0017/0022/0023/0024) ve
/// "table/index X already exists" (IF-NOT-EXISTS'siz CREATE re-run — 0014).
/// UNIQUE-violation / "no such table" / syntax vb. GERÇEK hatadır → yutulmaz.
fn is_benign_schema_conflict(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("duplicate column name") || m.contains("already exists")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Elle bakımlı MIGRATIONS listesi ↔ migrations/ klasörü senkron mu?
    /// (Yeni dosya ekleyip listeyi unutursan bu test kırılır.)
    #[test]
    fn migrations_listesi_klasorle_senkron() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .expect("migrations klasoru okunamadi")
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter_map(|n| n.strip_suffix(".sql").map(str::to_string))
            .collect();
        files.sort();
        let names: Vec<String> = MIGRATIONS.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(
            names, files,
            "migrations/*.sql <-> MIGRATIONS listesi uyusmuyor — yeni migration ekledin ama listeye satir eklemedin mi?"
        );
        // Sıralılık + benzersizlik (dosya-adı = versiyon anahtarı).
        for w in names.windows(2) {
            assert!(w[0] < w[1], "MIGRATIONS sirasiz: {} >= {}", w[0], w[1]);
        }
    }

    /// Gömülü her dosya en az 1 statement üretmeli; hiçbir statement yorum
    /// artığı içermemeli (splitter yorumları soymuş olmalı).
    #[test]
    fn tum_migrationlar_bolunebiliyor() {
        for (name, sql) in MIGRATIONS {
            let stmts = split_sql_statements(sql);
            assert!(!stmts.is_empty(), "{name}: hic statement cikmadi");
            for s in &stmts {
                assert!(!s.trim().is_empty(), "{name}: bos statement");
                assert!(
                    !s.contains("--"),
                    "{name}: statement icinde yorum artigi kaldi: {s}"
                );
            }
        }
    }

    /// Gerçek tuzak vakası: 0014'ün CREATE TABLE'ında inline yorum içinde `;`
    /// var — naif split tabloyu ortadan keserdi. Splitter 2 statement çıkarmalı
    /// (CREATE TABLE + CREATE INDEX) ve CREATE TABLE bütün kalmalı.
    #[test]
    fn yorum_icindeki_noktali_virgul_statement_kesmiyor() {
        let sql = MIGRATIONS
            .iter()
            .find(|(n, _)| *n == "0014_device_link")
            .unwrap()
            .1;
        let stmts = split_sql_statements(sql);
        assert_eq!(stmts.len(), 2, "0014: CREATE TABLE + CREATE INDEX beklenir");
        assert!(stmts[0].contains("expires_at") && stmts[0].contains("link_code"));
        assert!(stmts[1].starts_with("CREATE INDEX"));
    }

    #[test]
    fn splitter_string_literal_ve_blok_yorum() {
        let sql = "INSERT INTO t VALUES ('a;b', 'it''s'); /* yorum; icinde */ SELECT 1;\n-- kuyruk yorumu\n";
        let stmts = split_sql_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], "INSERT INTO t VALUES ('a;b', 'it''s')");
        assert_eq!(stmts[1], "SELECT 1");
    }

    /// Tek-batch sıra sözleşmesi: dosya1-stmt'leri → dosya1-track →
    /// dosya2-stmt'leri → dosya2-track... Yorum-only dosya yalnız track üretir.
    #[test]
    fn tek_batch_birlestirme_sirasi() {
        let pending: [(&str, &str); 3] = [
            (
                "0001_a",
                "CREATE TABLE a (id INTEGER); CREATE INDEX ia ON a(id);",
            ),
            ("0002_b", "-- yalniz yorum, statement yok\n"),
            ("0003_c", "ALTER TABLE a ADD COLUMN x TEXT;"),
        ];
        let merged = merge_pending_statements(&pending);
        assert_eq!(
            merged,
            vec![
                MergedStmt::Sql("CREATE TABLE a (id INTEGER)".into()),
                MergedStmt::Sql("CREATE INDEX ia ON a(id)".into()),
                MergedStmt::Track("0001_a".into()),
                MergedStmt::Track("0002_b".into()),
                MergedStmt::Sql("ALTER TABLE a ADD COLUMN x TEXT".into()),
                MergedStmt::Track("0003_c".into()),
            ]
        );
    }

    /// Bekleyen boş → boş vektör (run_migrations zaten erken döner ama saf
    /// fonksiyonun sözleşmesi de net olsun).
    #[test]
    fn tek_batch_bos_bekleyen_bos_doner() {
        assert!(merge_pending_statements(&[]).is_empty());
    }

    /// Gerçek gömülü liste üstünde bütünlük: birleştirilmiş uzunluk =
    /// toplam-statement + dosya-başına-1-track; her dosyanın track'i kendi
    /// statement'larından SONRA gelir (taze-fork ilk-boot senaryosunun aynısı).
    #[test]
    fn tek_batch_tum_migrationlar_stmt_arti_track() {
        let pending: Vec<(&str, &str)> = MIGRATIONS.to_vec();
        let merged = merge_pending_statements(&pending);
        let stmt_toplam: usize = MIGRATIONS
            .iter()
            .map(|(_, sql)| split_sql_statements(sql).len())
            .sum();
        assert_eq!(merged.len(), stmt_toplam + MIGRATIONS.len());
        // Track sırası = MIGRATIONS sırası; son öğe son dosyanın track'i.
        let tracks: Vec<&String> = merged
            .iter()
            .filter_map(|m| match m {
                MergedStmt::Track(n) => Some(n),
                MergedStmt::Sql(_) => None,
            })
            .collect();
        let beklenen: Vec<String> = MIGRATIONS.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(tracks, beklenen.iter().collect::<Vec<_>>());
        assert_eq!(
            merged.last(),
            Some(&MergedStmt::Track(MIGRATIONS.last().unwrap().0.to_string()))
        );
    }

    #[test]
    fn benign_siniflandirma() {
        // Benign: çıplak-ALTER re-run + IF-NOT-EXISTS'siz CREATE re-run.
        assert!(is_benign_schema_conflict(
            "D1_ERROR: duplicate column name: role: SQLITE_ERROR"
        ));
        assert!(is_benign_schema_conflict("table link_requests already exists"));
        assert!(is_benign_schema_conflict(
            "index idx_link_requests_expiry already exists"
        ));
        // Gerçek hatalar yutulMAZ.
        assert!(!is_benign_schema_conflict("no such table: users"));
        assert!(!is_benign_schema_conflict(
            "UNIQUE constraint failed: users.email"
        ));
        assert!(!is_benign_schema_conflict("near \"CREATTE\": syntax error"));
    }

    #[test]
    fn wrangler_isim_normalize() {
        assert_eq!(normalize_migration_name("0001_init.sql"), "0001_init");
        assert_eq!(normalize_migration_name("0001_init"), "0001_init");
        assert_eq!(normalize_migration_name(" 0025_server_config.sql "), "0025_server_config");
    }

    /// Üretilen PEM, jwt.rs'in env-secret için kullandığı parser'la BİT-UYUMLU
    /// olmalı (aynı fonksiyon: `parse_signing_pem` — format uyum kanıtı) ve
    /// imza roundtrip'i geçmeli.
    #[test]
    fn jwt_pem_roundtrip_jwt_parser_ile_uyumlu() {
        use ed25519_dalek::{Signer, Verifier};
        let pem = generate_jwt_signing_pem().unwrap();
        // Gerçek newline'lı PEM: jwt.rs'in `\\n`→`\n` replace'i no-op kalmalı.
        assert!(pem.contains('\n') && !pem.contains("\\n"));
        let key = crate::auth::jwt::parse_signing_pem(&pem).expect("jwt.rs parser'i kabul etmeli");
        let msg = b"sezi self-provision roundtrip";
        let sig = key.sign(msg);
        key.verifying_key().verify(msg, &sig).unwrap();
    }

    #[test]
    fn invite_key_uretimi_b64u_32_byte() {
        let k = generate_admin_invite_key().unwrap();
        // 32 byte → b64url padding'siz 43 karakter.
        assert_eq!(k.len(), 43);
        assert!(crate::utils::b64u_decode(&k).unwrap().len() == 32);
    }

    /// Self-heal kapısı (2026-07-06 sezi-server2 vakası): bozuk D1 kaydı
    /// validate'i GEÇMEMELİ (→ yeniden-üretim yolu), üretilen taze anahtar
    /// GEÇMELİ (→ körü körüne kullanım yerine doğrulanmış kullanım).
    #[test]
    fn validate_jwt_pem_bozuk_kaydi_reddediyor_tazeyi_kabul_ediyor() {
        // Saha benzeri bozukluklar: boş, PEM-değil, gövdesi-çöp PEM, kırpılmış PEM.
        assert!(!validate_jwt_pem(""));
        assert!(!validate_jwt_pem("hic PEM degil"));
        assert!(!validate_jwt_pem(
            "-----BEGIN PRIVATE KEY-----\nQk9aVUsgS0FZSVQ=\n-----END PRIVATE KEY-----\n"
        ));
        let pem = generate_jwt_signing_pem().unwrap();
        let truncated = &pem[..pem.len() / 2];
        assert!(!validate_jwt_pem(truncated));
        // Taze üretim geçer (üretici ↔ doğrulayıcı uyumu).
        assert!(validate_jwt_pem(&pem));
        // wrangler-secret tarzı kaçışlı-newline PEM de geçer (parser replace'li).
        assert!(validate_jwt_pem(&pem.replace('\n', "\\n")));
    }

    #[test]
    fn validate_invite_key_bos_reddediyor_tazeyi_kabul_ediyor() {
        assert!(!validate_invite_key(""));
        assert!(!validate_invite_key("   \n\t"));
        assert!(validate_invite_key(&generate_admin_invite_key().unwrap()));
    }
}
