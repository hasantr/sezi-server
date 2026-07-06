//! Kota **Faz 1a** — upload depolama-kotası ZORLAMASI (0022 shadow-sayaçlarını okur).
//!
//! **FAIL-OPEN disiplini:** cap ya da sayaç OKUNAMAZSA (DB hatası / satır yok /
//! migration eksik) trafik KESİLMEZ. Reddetme YALNIZ: set-edilmiş (non-null)
//! cap ve `used + size > cap`. NULL cap = sınırsız — owner cap koymadıkça hiçbir
//! mevcut sunucu sürpriz kesinti yemez. Server DUMB/E2E-kör kalır: yalnız boyut
//! metadata'sı (content-length) sayılır, içerik asla.

use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

/// Upload kota kararı — SAF/test-edilebilir (DB'siz). Cap `None` → sınırsız.
/// Aşım = `used + size > cap` (tam-eşit SIĞAR, `>` kullanılır). Reddedilen
/// scope döner (öncelik: sunucu-toplam, sonra per-user); `None` = izin.
pub fn decide_upload(
    server_used: i64,
    user_used: i64,
    size: i64,
    max_server: Option<i64>,
    max_user: Option<i64>,
) -> Option<&'static str> {
    if let Some(cap) = max_server {
        if server_used + size > cap {
            return Some("server_storage");
        }
    }
    if let Some(cap) = max_user {
        if user_used + size > cap {
            return Some("user_storage");
        }
    }
    None
}

#[derive(Deserialize)]
struct CapsRow {
    max_storage_bytes: Option<i64>,
    max_user_storage_bytes: Option<i64>,
}

#[derive(Deserialize)]
struct ServerBytesRow {
    media_bytes: i64,
}

#[derive(Deserialize)]
struct UserBytesRow {
    bytes: i64,
}

/// Upload öncesi kota kontrolü — cap'ler + sayaçlar D1'den okunur, karar
/// `decide_upload`'a devredilir. Her okuma fail-open: cap-SELECT hata/satır-yok
/// → cap bilinmiyor → izin; sayaç hata/satır-yok → 0 (size tek başına cap'i
/// aşıyorsa reddetmek yine doğru — size content-length'ten kesin biliniyor).
/// İki cap da NULL ise sayaçlar HİÇ okunmaz (hızlı-yol: default kurulumda
/// upload başına tek ek SELECT).
pub async fn check_upload(db: &D1Database, uploader_id: &str, size: i64) -> Option<&'static str> {
    let caps = match db
        .prepare(
            "SELECT max_storage_bytes, max_user_storage_bytes \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first::<CapsRow>(None)
        .await
    {
        Ok(Some(row)) => row,
        // Satır yok / DB hatası / 0023 migrate edilmemiş → cap bilinmiyor → izin.
        _ => return None,
    };
    if caps.max_storage_bytes.is_none() && caps.max_user_storage_bytes.is_none() {
        return None; // hızlı-yol: cap konmamış → sayaç okumaya gerek yok
    }

    // Sayaçlar yalnız ilgili cap set'liyse okunur (gereksiz D1 sorgusu yok);
    // decide_upload cap None iken sayaca zaten bakmaz → 0 zararsız.
    let server_used = if caps.max_storage_bytes.is_some() {
        db.prepare("SELECT media_bytes FROM server_stats WHERE id = 1 LIMIT 1")
            .first::<ServerBytesRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.media_bytes)
            .unwrap_or(0)
    } else {
        0
    };
    let user_used = if caps.max_user_storage_bytes.is_some() {
        match db
            .prepare("SELECT bytes FROM user_storage WHERE user_id = ? LIMIT 1")
            .bind(&[d1_text(uploader_id)])
        {
            Ok(stmt) => stmt
                .first::<UserBytesRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.bytes)
                .unwrap_or(0),
            Err(_) => 0,
        }
    } else {
        0
    };

    decide_upload(
        server_used,
        user_used,
        size,
        caps.max_storage_bytes,
        caps.max_user_storage_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::decide_upload;

    #[test]
    fn cap_altinda_izin() {
        assert_eq!(decide_upload(100, 50, 10, Some(200), Some(100)), None);
    }

    #[test]
    fn server_asimi_reddedilir() {
        assert_eq!(
            decide_upload(195, 0, 10, Some(200), None),
            Some("server_storage")
        );
    }

    #[test]
    fn user_asimi_reddedilir() {
        assert_eq!(
            decide_upload(0, 95, 10, Some(1000), Some(100)),
            Some("user_storage")
        );
    }

    #[test]
    fn null_cap_sinirsiz() {
        assert_eq!(decide_upload(1 << 52, 1 << 52, 1 << 40, None, None), None);
    }

    #[test]
    fn sinir_tam_esit_sigar() {
        // used + size == cap → İZİN (karşılaştırma `>`, `>=` değil).
        assert_eq!(decide_upload(190, 90, 10, Some(200), Some(100)), None);
    }
}
