//! Acknowledging stored frames: remove them from `pending` and tell their senders.
//!
//! A pure move out of the WS `ack` arm (`ws.rs`), so the same two steps can run without a
//! socket — the bot inbox acks the frames its engine opened (docs/BOTS_BUILD.md §2.3). The WS arm
//! still answers `ack_ok` between the two steps, exactly as before the move.

use super::*;

/// One acked `pending` row, as read just before it is deleted.
#[derive(Deserialize)]
pub(crate) struct AckRow {
    pub(crate) id: i64,
    pub(crate) sender_id: String,
    /// M2-S2.2: this row's recipient device (carried into the delivered forward).
    #[serde(default)]
    pub(crate) device_id: Option<String>,
}

/// One forward's worth of acked rows: the sender and the recipient device the receipt is
/// scoped to, the row ids, and their msg_uids PARALLEL to them (empty string when unknown).
pub(crate) type AckGroup = ((String, Option<String>), Vec<i64>, Vec<String>);

/// Group acked rows by (sender, recipient_device), pure.
///
/// M2-S2.2: grouped so a delivery-failed self-heal targets the right device pair (D1 BLOCKER).
/// With N=1 there is a single device → a single group; when the row's device is NULL (the
/// backfill window) fall back to `ack_device`. A1 completion: each group carries a uid array
/// PARALLEL to its ids — `/forward-delivered` → apply_receipt("delivered", .., uids) →
/// receipt_state.msg_uid → the sibling advances its oc- row on the next cursor sync.
pub(crate) fn group_acks(
    rows: Vec<AckRow>,
    ids: &[i64],
    uids: &[String],
    ack_device: Option<&str>,
) -> Vec<AckGroup> {
    use std::collections::HashMap;
    let id_to_uid: HashMap<i64, String> = ids
        .iter()
        .copied()
        .zip(uids.iter().cloned())
        .filter(|(_, u)| !u.is_empty())
        .collect();
    let mut by_key: HashMap<(String, Option<String>), Vec<i64>> = HashMap::new();
    for r in rows {
        let dev = r.device_id.or_else(|| ack_device.map(str::to_string));
        by_key.entry((r.sender_id, dev)).or_default().push(r.id);
    }
    by_key
        .into_iter()
        .map(|(key, acked)| {
            let uids = acked
                .iter()
                .map(|id| id_to_uid.get(id).cloned().unwrap_or_default())
                .collect();
            (key, acked, uids)
        })
        .collect()
}

/// Acked ids per statement: the bound-parameter cap less the device bind.
pub(crate) const ACK_IDS_PER_STATEMENT: usize = crate::d1util::MAX_BOUND_PARAMS - 1;

/// The SELECT and the DELETE of `n` acked ids, scoped to one device (its id is the last bind).
/// Pure, so the cap can be tested against a capped SQLite.
pub(crate) fn ack_sql(n: usize) -> (String, String) {
    let marks = crate::d1util::marks(n);
    let dev_clause = " AND (device_id = ? OR device_id IS NULL)";
    (
        format!("SELECT id, sender_id, device_id FROM pending WHERE id IN ({marks}){dev_clause}"),
        format!("DELETE FROM pending WHERE id IN ({marks}){dev_clause}"),
    )
}

impl UserInbox {
    /// SELECT and DELETE the acked rows, scoped to `ack_device`.
    ///
    /// Ack isolation: SELECT+DELETE only rows belonging to THIS device, plus NULL ones —
    /// `AND (device_id = ? OR device_id IS NULL)`. A NULL pending row is legitimate: it belongs to
    /// a member who never published a device list (the group fallback's LEFT JOIN), who is
    /// therefore a SINGLE logical device that must be able to ack its own rows, or the message is
    /// never removed and redelivers forever. Safe only because the 1:1 path REQUIRES a device_id,
    /// so NULL never means ambiguity. Revisit if a multi-device user can ever own a NULL row.
    pub(crate) fn delete_acked_rows(
        &self,
        ids: &[i64],
        ack_device: Option<&str>,
    ) -> Result<Vec<AckRow>> {
        // `ack_device` is an Option only because a socket accepted before 2026-11-03 may carry no
        // attachment — not because a token can lack a device claim. Such a socket acks NOTHING:
        // with no device clause its ack deleted every device's rows, and when it acked false the
        // frames it could not decrypt, a sibling's messages were lost (audit finding #7). The
        // `OR device_id IS NULL` above is a different thing: it is about the pending ROW.
        let Some(device) = ack_device else {
            return Ok(Vec::new());
        };
        let storage = self.state.storage();
        let sql = storage.sql();
        let mut rows: Vec<AckRow> = Vec::with_capacity(ids.len());
        // The ack list is the client's and uncapped; a statement is held to the platform's
        // bound-parameter cap, the device bind included.
        for chunk in ids.chunks(ACK_IDS_PER_STATEMENT) {
            let (select_sql, del_sql) = ack_sql(chunk.len());
            let mut vals: Vec<JsValue> =
                chunk.iter().map(|i| JsValue::from_f64(*i as f64)).collect();
            vals.push(JsValue::from_str(device));
            let cursor = sql.exec_raw(&select_sql, Some(vals.clone()))?;
            rows.extend(cursor.to_array::<AckRow>()?);
            sql.exec_raw(&del_sql, Some(vals))?;
        }
        Ok(rows)
    }

    /// Forward `delivered` (success) or `delivery_failed` to each sender's inbox.
    ///
    /// `uids` is PARALLEL to `ids`. The delivered receipt carries uids like read does, so the
    /// sender's SIBLING can advance its `oc-{msg_uid}` row to Delivered; the mapping travels as a
    /// uid array in `ids` order on `/forward-delivered`. No `recipient_id` → nothing is forwarded.
    pub(crate) async fn forward_acked_rows(
        &self,
        rows: Vec<AckRow>,
        ids: &[i64],
        uids: &[String],
        success: bool,
        ack_device: Option<&str>,
        recipient_id: Option<&str>,
    ) -> Result<()> {
        let Some(rid) = recipient_id else {
            return Ok(());
        };
        let namespace = self.env.durable_object("USER_INBOX")?;
        // `success=true` → /forward-delivered (second tick for the sender).
        // `success=false` → /forward-delivery-failed (sender moves to failedDelivery → the UI
        //  shows a 1.5 tick and auto-retries).
        let forward_path = if success {
            "https://do.sezgi/forward-delivered"
        } else {
            "https://do.sezgi/forward-delivery-failed"
        };
        for ((sender_id, recipient_device), acked, uids) in group_acks(rows, ids, uids, ack_device) {
            let stub = namespace.id_from_name(&sender_id)?.get_stub()?;
            let payload = serde_json::json!({
                "from": rid,
                "recipient_device_id": recipient_device,
                "ids": acked,
                "uids": uids,
            })
            .to_string();
            let mut init = RequestInit::new();
            init.with_method(Method::Post);
            init.with_body(Some(payload.into()));
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            init.with_headers(headers);
            let do_req = Request::new_with_init(forward_path, &init)?;
            let _ = stub.fetch_with_request(do_req).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ack_sql, group_acks, AckRow, ACK_IDS_PER_STATEMENT};

    #[test]
    fn a_long_ack_list_is_cut_under_the_bound_parameter_cap() {
        // The ack list is the client's and uncapped; one statement over 100 binds fails whole
        // on the platform, so nothing would be acked and every row would redeliver forever.
        let db = rusqlite::Connection::open_in_memory().unwrap();
        crate::test_schema::cap_binds_like_d1(&db);
        db.execute_batch("CREATE TABLE pending (id INTEGER PRIMARY KEY, sender_id TEXT, device_id TEXT);")
            .unwrap();
        for id in 1..=250i64 {
            let dev = if id % 2 == 0 { "mine" } else { "sibling" };
            db.execute("INSERT INTO pending VALUES (?1, 's', ?2)", rusqlite::params![id, dev])
                .unwrap();
        }
        let ids: Vec<i64> = (1..=250).collect();
        let (_, one) = ack_sql(ids.len());
        let mut all: Vec<rusqlite::types::Value> = ids.iter().map(|i| (*i).into()).collect();
        all.push("mine".to_string().into());
        assert!(db.execute(&one, rusqlite::params_from_iter(&all)).is_err());
        for chunk in ids.chunks(ACK_IDS_PER_STATEMENT) {
            let (_, del) = ack_sql(chunk.len());
            let mut vals: Vec<rusqlite::types::Value> = chunk.iter().map(|i| (*i).into()).collect();
            vals.push("mine".to_string().into());
            db.execute(&del, rusqlite::params_from_iter(&vals)).unwrap();
        }
        let left: i64 = db
            .query_row("SELECT COUNT(*) FROM pending WHERE device_id = 'mine'", [], |r| r.get(0))
            .unwrap();
        let sibling: i64 = db
            .query_row("SELECT COUNT(*) FROM pending WHERE device_id = 'sibling'", [], |r| r.get(0))
            .unwrap();
        assert_eq!((left, sibling), (0, 125), "mine all acked, the sibling's untouched");
    }

    fn row(id: i64, sender: &str, device: Option<&str>) -> AckRow {
        AckRow { id, sender_id: sender.into(), device_id: device.map(str::to_string) }
    }

    #[test]
    fn acks_group_by_sender_and_device_with_their_uids_in_order() {
        let rows = vec![row(1, "a", Some("d1")), row(2, "b", None), row(3, "a", Some("d1"))];
        let ids = [1, 2, 3];
        let uids = ["u1".to_string(), String::new(), "u3".to_string()];
        let mut groups = group_acks(rows, &ids, &uids, Some("mine"));
        groups.sort();
        assert_eq!(
            groups,
            vec![
                (("a".into(), Some("d1".into())), vec![1, 3], vec!["u1".into(), "u3".into()]),
                // A NULL row device falls back to the acking device; an unknown uid stays "".
                (("b".into(), Some("mine".into())), vec![2], vec![String::new()]),
            ]
        );
    }
}
