//! Çoklu-cihaz adresleme (M1) — imzalı cihaz-listesi sakla/dağıt.
//!
//! `PUT /devices/list`        — birincil-imzalı listeyi yükle (rev-artışlı upsert).
//! `GET /devices/list/:user`  — bir kullanıcının güncel imzalı listesini çek.
//!
//! Sıfır-güven: server listeyi DOĞRULAR ama üretemez. İmza, `users.identity_pubkey`
//! (= birincil cihazın Ed25519'u) ile doc_json'un AYNEN gelen baytları üzerinden
//! doğrulanır (JWS modeli — yeniden serileştirme YOK). Asıl güvence client'ta,
//! buradaki kontroller savunma-derinliği + tutarlılık.

pub mod handlers;
pub mod link;
