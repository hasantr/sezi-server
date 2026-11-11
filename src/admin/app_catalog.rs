//! The server's app catalog over HTTP (Wave C5, `crate::app_catalog`).
//!
//! - **GET /apps/catalog** — every active member: `{"entries":[…]}`. A group admin's app offers
//!   them in its "add app" sheet.
//! - **GET /apps/catalog/:id** — every active member: the bundle's bytes as the publisher shipped
//!   them (plaintext, signed; the module doc says why), only while they hash to the id. The admin's
//!   core checks their BLAKE3 against the id and the publisher signature before anything is
//!   assigned.
//! - **PUT /admin/apps/catalog** — the OWNER: the bundle tar as the body. `400 app-catalog/bad-bundle`,
//!   `400 app-catalog/not-signed`, `400 plugin/not-approved` (an allowlist server and a bundle it does
//!   not approve), `400 app-catalog/full`. The same bundle again is the same entry. Answers the list.
//! - **DELETE /admin/apps/catalog/:id** — the OWNER; the bundle's bytes go with the row. Rooms that
//!   installed it keep their app: its code was uploaded to each room. Answers the list.
//!
//! No media store = `503 media_not_configured` on every route, before anything else is read
//! (after the authorization check). Which apps a server offers is the owner's call (decision D1);
//! a group admin only picks. What each route does is `crate::app_catalog_flow`; this file
//! authorizes, reads the request and adapts the media store and D1 to its ports.

use crate::app_catalog::{self as catalog, Accepted, DbRow, COUNT_SQL, DELETE_SQL, INSERT_SQL, LIST_SQL, STORE_SQL};
use crate::app_catalog_flow::{self as flow, CatalogBlobs, CatalogRows, Outcome};
use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::storage::{PlacementError, StorageClass, StorageRouter};
use worker::*;

/// The media store as the catalog's port.
struct RouterBlobs(StorageRouter);

impl CatalogBlobs for RouterBlobs {
    type PutErr = PlacementError;

    async fn put(&self, key: &str, bytes: Vec<u8>) -> std::result::Result<String, PlacementError> {
        self.0.put_new(StorageClass::PluginCode, key, bytes, "application/x-tar").await
    }

    async fn get(&self, store_id: &str, key: &str) -> std::result::Result<Option<Vec<u8>>, ()> {
        self.0.get(store_id, key).await.map(|o| o.map(|o| o.bytes)).map_err(|_| ())
    }

    async fn delete(&self, store_id: &str, key: &str) {
        let _ = self.0.delete(store_id, key).await;
    }
}

/// The `app_catalog` table on D1 as the catalog's port.
struct D1Rows(D1Database);

impl CatalogRows for D1Rows {
    async fn list(&self) -> Vec<DbRow> {
        self.0
            .prepare(LIST_SQL)
            .all()
            .await
            .and_then(|r| r.results::<DbRow>())
            .unwrap_or_default()
    }

    async fn count(&self) -> std::result::Result<i64, String> {
        #[derive(serde::Deserialize)]
        struct Count {
            n: i64,
        }
        self.0
            .prepare(COUNT_SQL)
            .first::<Count>(None)
            .await
            .map(|c| c.map(|c| c.n).unwrap_or(0))
            .map_err(|e| e.to_string())
    }

    async fn store_id_of(&self, id: &str) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct Row {
            store_id: String,
        }
        self.0
            .prepare(STORE_SQL)
            .bind(&[d1_text(id)])
            .ok()?
            .first::<Row>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.store_id)
    }

    async fn insert(
        &self,
        a: &Accepted,
        size: i64,
        store_id: &str,
        by: &str,
        at_ms: i64,
    ) -> std::result::Result<(), String> {
        let stmt = self
            .0
            .prepare(INSERT_SQL)
            .bind(&[
                d1_text(&a.id),
                d1_text(&a.code_hash),
                d1_text(&a.app_id),
                d1_text(&a.name),
                d1_text(&a.version),
                d1_text(&a.publisher_key),
                d1_text(&a.publisher_name),
                d1_text(&a.manifest),
                d1_int(size),
                d1_text(store_id),
                d1_text(by),
                d1_int(at_ms),
            ])
            .map_err(|e| e.to_string())?;
        stmt.run().await.map(|_| ()).map_err(|e| e.to_string())
    }

    async fn delete(&self, id: &str) -> std::result::Result<(), String> {
        let stmt = self.0.prepare(DELETE_SQL).bind(&[d1_text(id)]).map_err(|e| e.to_string())?;
        stmt.run().await.map(|_| ()).map_err(|e| e.to_string())
    }
}

/// The store, or `None` on a Lite relay (no media store, or none it can reach).
async fn store(env: &Env) -> Option<RouterBlobs> {
    match StorageRouter::from_env(env).await {
        Ok(r) if r.any_available() => Some(RouterBlobs(r)),
        _ => None,
    }
}

fn respond(outcome: Outcome<PlacementError>) -> Result<Response> {
    match outcome {
        Outcome::List(rows) => Response::from_json(&catalog::view(&rows)),
        Outcome::Bytes(bytes) => {
            let mut resp = Response::from_bytes(bytes)?;
            resp.headers_mut().set("content-type", "application/x-tar")?;
            Ok(resp)
        }
        Outcome::Refused(status, code) => json_err(status, code),
        Outcome::PutFailed(e) => crate::storage::placement_err_response(e),
        Outcome::Failed(e) => Err(Error::RustError(e)),
    }
}

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = require_active_auth(&req, &ctx.env).await {
        return Ok(resp);
    }
    let blobs = store(&ctx.env).await;
    respond(flow::list(blobs.as_ref(), &D1Rows(ctx.env.d1("DB")?)).await)
}

pub async fn fetch(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = require_active_auth(&req, &ctx.env).await {
        return Ok(resp);
    }
    let blobs = store(&ctx.env).await;
    let id = ctx.param("id").cloned().unwrap_or_default();
    respond(flow::fetch(blobs.as_ref(), &D1Rows(ctx.env.d1("DB")?), &id).await)
}

pub async fn add(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let Some(blobs) = store(&ctx.env).await else {
        return json_err(flow::NO_STORE.0, flow::NO_STORE.1);
    };
    let declared: usize = req
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if declared == 0 || declared > catalog::MAX_BYTES {
        return json_err(400, catalog::BAD_BUNDLE);
    }
    let bytes = req.bytes().await?;
    let db = ctx.env.d1("DB")?;
    let list = crate::plugin_allowlist::read(&db).await;
    let at = crate::utils::now_ms() as i64;
    respond(flow::add(Some(&blobs), &D1Rows(db), bytes, &list, &user_id, at).await)
}

pub async fn remove(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let blobs = store(&ctx.env).await;
    let id = ctx.param("id").cloned().unwrap_or_default();
    respond(flow::remove(blobs.as_ref(), &D1Rows(ctx.env.d1("DB")?), &id).await)
}
