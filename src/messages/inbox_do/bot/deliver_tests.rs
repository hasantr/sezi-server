//! The webhook queue's and the taken-sources' SQL, on rusqlite (the `dedup_sql_tests` style).

use super::super::store::TABLES;
use super::super::updates::{UPDATE_CONFIRM, UPDATE_PUSH};
use super::*;
use rusqlite::{params, Connection};

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    for t in TABLES.iter().chain(super::super::deliver_order::TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    c
}

fn push(c: &Connection, at: i64) -> i64 {
    c.query_row(UPDATE_PUSH, params!["{}", at], |r| r.get(0)).unwrap()
}

fn due(c: &Connection) -> Vec<i64> {
    let mut s = c.prepare(HOOK_DUE).unwrap();
    s.query_map([10], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}

fn next(c: &Connection) -> Option<i64> {
    c.query_row(HOOK_NEXT, [], |r| r.get(0)).ok()
}

#[test]
fn the_webhook_queue_goes_in_order_and_its_head_sets_the_alarm() {
    let c = db();
    assert_eq!(next(&c), None, "nothing waits: no alarm");
    let (a, b) = (push(&c, 1_000), push(&c, 2_000));
    assert_eq!(due(&c), vec![a, b]);
    assert_eq!(next(&c), Some(0), "a fresh update is due now");
    c.execute(HOOK_RETRY, params![50_000, a]).unwrap();
    assert_eq!(next(&c), Some(50_000), "the head's back-off holds the queue, b does not jump it");
    c.execute(HOOK_DONE, [a]).unwrap();
    assert_eq!(due(&c), vec![b]);
    let waiting: i64 = c.query_row(WAITING_SINCE, [], |r| r.get(0)).unwrap();
    assert_eq!(waiting, 2_000);
}

#[test]
fn a_polled_update_is_no_longer_owed_to_the_webhook_nor_waiting() {
    let c = db();
    let a = push(&c, 1_000);
    c.execute("UPDATE bot_updates SET delivered_at = 5 WHERE update_id = ?", [a]).unwrap();
    assert!(due(&c).is_empty());
    let waiting: Option<i64> = c.query_row(WAITING_SINCE, [], |r| r.get(0)).unwrap();
    assert_eq!(waiting, None);
}

#[test]
fn taken_sources_are_read_once_and_orphans_go() {
    let c = db();
    let (a, b, d) = (push(&c, 1), push(&c, 2), push(&c, 3));
    c.execute(SRC_PUT, params![a, "alice", 11, "m-1"]).unwrap();
    c.execute(SRC_PUT, params![b, "bob", 12, ""]).unwrap();
    c.execute(SRC_PUT, params![d, "alice", 13, "m-3"]).unwrap();
    let read = |first: i64, last: i64| -> Vec<(String, i64, String)> {
        let mut s = c.prepare(SRC_TAKEN).unwrap();
        s.query_map([first, last], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(read(a, b).len(), 2);
    c.execute(SRC_DROP, [a, b]).unwrap();
    assert!(read(a, b).is_empty(), "taken once");
    // A poll handed all three out; its next offset confirms them.
    c.execute(super::super::updates::UPDATE_MARK, [9_999, a, d]).unwrap();
    c.execute(UPDATE_CONFIRM, [d + 1]).unwrap();
    c.execute(SRC_ORPHANS, []).unwrap();
    assert!(read(a, d).is_empty(), "an update's source goes with it");
}

#[test]
fn taken_frames_group_per_member_with_parallel_uids() {
    let rows = vec![
        ("alice".to_string(), 11, Some("m-1".to_string())),
        ("bob".to_string(), 12, None),
        ("alice".to_string(), 13, Some("m-3".to_string())),
    ];
    assert_eq!(
        group_taken(&rows),
        vec![
            ("alice".to_string(), vec![11, 13], vec!["m-1".to_string(), "m-3".to_string()]),
            ("bob".to_string(), vec![12], vec![String::new()]),
        ]
    );
}

/// The body of `fn <name>` in `src`, up to its closing brace at method depth.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src.find(&format!("fn {name}(")).expect(name);
    &src[start..start + src[start..].find("\n    }\n").expect("end")]
}

/// A program bot the owner turned off went on receiving every member's message by webhook — and
/// each one read as "the program has it" — while polling answered `bot/disabled` (2026-10-26).
/// The round asks the same gate the built-in runner does, before it POSTs or marks anything read.
#[test]
fn a_bot_turned_off_is_posted_nothing_and_marks_nothing_read() {
    let src = include_str!("deliver.rs");
    let round = fn_body(src, "bot_deliver_webhooks");
    let gate = round.find("round_gate(").expect("the webhook round never asks whether the bot is on");
    for step in ["webhook::post(", "bot_updates_taken("] {
        assert!(gate < round.find(step).expect(step), "{step} before the gate");
    }
    // A program that never answers fails its POST after a bound instead of holding the tick (and
    // the replies and room posts that drain after this round).
    let post = round.find("crate::bots::webhook::post(").expect("the POST");
    assert!(round[post..].contains("with_timeout(post, WEBHOOK_TIMEOUT_MS)"), "an unbounded webhook POST");
    // `/bot/wake` (the owner turning it back on) ends the hold at once.
    assert!(fn_body(include_str!("builtin.rs"), "bot_wake").contains("KV_WEBHOOK_HOLD"));
}

/// `setWebhook` has refused a URL into the relay's own network since 22c34670, but a URL stored
/// before that stayed in the inbox and was POSTed to on every update (audit 2026-10-26, note 1.4).
/// The rule is asked again at delivery: a refused webhook gets nothing, holds the queue as a
/// failing one does, arms no alarm, and the owner's listing says so.
#[test]
fn a_webhook_stored_before_the_url_rule_is_judged_again_at_delivery() {
    let s = || Some("secret".to_string());
    for old in ["http://192.168.1.1/hook", "https://10.0.0.5/x", "https://router.lan/x", "https://nas.local/x", "https://localhost/x"] {
        assert_eq!(webhook_at_delivery(Some(old.into()), s(), false), Hook::Refused, "{old}");
    }
    let live = "https://script.google.com/macros/s/abc/exec";
    assert_eq!(webhook_at_delivery(Some(live.into()), s(), false), Hook::Live(live.into(), "secret".into()));
    assert_eq!(
        webhook_at_delivery(Some("http://192.168.1.1/hook".into()), s(), true),
        Hook::Live("http://192.168.1.1/hook".into(), "secret".into()),
        "the lab escape lifts it here as at the set"
    );
    assert_eq!(webhook_at_delivery(None, s(), false), Hook::None);
    assert_eq!(webhook_at_delivery(Some(live.into()), None, false), Hook::None, "nothing to sign with");

    let src = include_str!("deliver.rs");
    let code = src.split("#[cfg(test)]").next().unwrap();
    // Every reader of the stored webhook goes through the judgement: the round and its alarm.
    for f in ["bot_deliver_webhooks", "bot_webhook_next"] {
        let body = fn_body(code, f);
        assert!(body.contains("self.bot_webhook()"), "{f} reads the webhook unjudged");
        assert!(!body.contains("kv_get(\"webhook_url\")"), "{f} reads the raw URL");
    }
    let round = fn_body(code, "bot_deliver_webhooks");
    assert!(round.find("Hook::Live(").unwrap() < round.find("webhook::post(").unwrap());
    // What the owner sees: `/bot/state` and `GET /admin/bots`.
    assert!(fn_body(include_str!("mod.rs"), "bot_state").contains("\"webhook_refused\""));
    assert!(include_str!("../../../bots/admin.rs").contains("v[\"webhook_refused\"]"));
}

#[test]
fn a_held_webhook_queue_waits_for_the_hold_and_an_empty_one_arms_nothing() {
    assert_eq!(webhook_next(None, Some(9_000)), None, "nothing waits: no alarm, held or not");
    assert_eq!(webhook_next(Some(0), None), Some(0), "due now");
    assert_eq!(webhook_next(Some(0), Some(9_000)), Some(9_000), "off: not a hot loop");
    assert_eq!(webhook_next(Some(20_000), Some(9_000)), Some(20_000), "a back-off past the hold");
}

/// `setWebhook` wrote the URL and answered 204, arming nothing: a backlog left from polling was
/// not POSTed until the next member's frame woke the inbox, and could expire at 24 h first
/// (review 2026-10-27, #4). Every door that creates work arms the alarm; this one too.
#[test]
fn setting_a_webhook_or_its_renewed_secret_arms_the_alarm() {
    let code = include_str!("deliver.rs").split("#[cfg(test)]").next().unwrap();
    let set = fn_body(code, "bot_set_webhook");
    let stored = set.find("kv_put(\"webhook_url\"").expect("the URL is stored");
    let arm = set.find("arm_alarm_within(0)").expect("setWebhook arms no alarm");
    assert!(stored < arm, "armed before the URL is in place");
    let renew = fn_body(code, "bot_set_webhook_secret");
    let stored = renew.find("kv_put(\"webhook_secret\"").expect("the secret is stored");
    let arm = renew.find("arm_alarm_within(0)").expect("a renewed secret arms no alarm");
    assert!(stored < arm, "armed before the secret is in place");
    // The routes await them: an alarm armed inside a future nobody polls is never armed.
    let routes = include_str!("mod.rs");
    for f in ["bot_set_webhook(", "bot_set_webhook_secret("] {
        let at = routes.find(&format!("self.{f}")).expect(f);
        assert!(routes[at..at + 80].contains(".await"), "{f} is not awaited");
    }
}
