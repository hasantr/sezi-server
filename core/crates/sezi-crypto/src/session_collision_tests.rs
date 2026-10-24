//! What happens when both ends open an Olm session at the same instant.
//!
//! Not a rare interleaving — a call forces it. Each end must send its own ICE candidates, so each
//! opens a session onto the other before either has heard back. With one session slot per device
//! both ends then store the session the PEER opened, neither can read the other, and recovery
//! cannot rescue it: the one-time key was consumed by the first PreKey and can never be claimed
//! twice. Measured on two real devices as `unknown one-time key`, every attempt, both directions,
//! while text kept working — because in a text chat only one side usually speaks first.

use crate::messaging::*;
use sezi_protocol::inner::InnerMessage;
use vodozemac::olm::Account;

/// One end of a pair: its pickled account plus what a peer needs to start a session with it.
struct Party {
    blob: String,
    key: [u8; 32],
    x_pub: String,
    otks: Vec<String>,
}

fn party(seed: u8) -> Party {
    let mut account = Account::new();
    account.generate_one_time_keys(4);
    let x_pub = account.identity_keys().curve25519.to_base64();
    let otks: Vec<String> = account
        .one_time_keys()
        .into_values()
        .map(|k| k.to_base64())
        .collect();
    account.mark_keys_as_published();
    let key = [seed; 32];
    Party {
        blob: account.pickle().encrypt(&key),
        key,
        x_pub,
        otks,
    }
}

fn text(body: &str) -> InnerMessage {
    InnerMessage::Text { body: body.into() }
}

fn body_of(inner: &InnerMessage) -> &str {
    match inner {
        InnerMessage::Text { body } => body.as_str(),
        other => panic!("expected a text message, got {other:?}"),
    }
}

/// Open a session onto `to`, claiming one of its one-time keys (first contact).
fn first_message(from: &Party, to: &Party, otk: &str, body: &str) -> EncryptedMessage {
    encrypt_inner_to_peer(
        from.blob.clone(),
        from.key.to_vec(),
        to.x_pub.clone(),
        Some(otk.to_string()),
        None,
        text(body),
        None,
        None,
    )
    .expect("first message")
}

/// Send on an established session.
fn next_message(from: &Party, to: &Party, session: &str, body: &str) -> EncryptedMessage {
    encrypt_inner_to_peer(
        from.blob.clone(),
        from.key.to_vec(),
        to.x_pub.clone(),
        None,
        Some(session.to_string()),
        text(body),
        None,
        None,
    )
    .expect("next message")
}

fn decrypt(who: &Party, candidates: &[String], envelope: &str) -> Result<DecryptedPayload, String> {
    decrypt_payload_from_peer_sessions(
        &who.blob,
        &who.key,
        candidates,
        envelope.to_string(),
        None,
    )
    .map_err(|e| format!("{e:?}"))
}

/// The error text of a decrypt that must fail.
///
/// Deliberately not `expect_err`: that requires `Debug` on the success type, and a
/// `DecryptedPayload` carries session pickles — secret material that must never end up in a panic
/// message or a CI log.
fn decrypt_err(who: &Party, candidates: &[String], envelope: &str) -> String {
    match decrypt(who, candidates, envelope) {
        Ok(_) => panic!("expected this decrypt to fail"),
        Err(e) => e,
    }
}

/// The defect, reproduced and then survived.
#[test]
fn a_message_sent_on_a_displaced_session_still_decrypts() {
    let a = party(1);
    let b = party(2);

    // Simultaneous opens: A onto B, B onto A.
    let a_to_b = first_message(&a, &b, &b.otks[0], "from A");
    let b_to_a = first_message(&b, &a, &a.otks[0], "from B");
    let session_x = a_to_b.new_session_blob.clone(); // A's view of the session A opened
    let session_y = b_to_a.new_session_blob.clone(); // B's view of the session B opened

    // A receives B's PreKey. Its own session cannot read it, so an inbound one is built.
    // `used_session=None` states the collision rather than leaving it to be inferred.
    let at_a = decrypt(&a, std::slice::from_ref(&session_x), &b_to_a.envelope_b64).expect("A reads B");
    assert_eq!(body_of(&at_a.payload.inner), "from B");
    assert!(
        at_a.used_session.is_none(),
        "neither end can read the other's opening message with its own session — that IS the \
         collision, and it is what displaces a working session",
    );
    let a_current = at_a.new_session_blob; // A's current is now the session B opened
    let a_archive = [session_x]; // displaced; the old single-slot write simply lost this

    // B goes through the mirror image and ends up holding the session A opened.
    let at_b = decrypt(&b, &[session_y], &a_to_b.envelope_b64).expect("B reads A");
    assert!(at_b.used_session.is_none());
    let b_current = at_b.new_session_blob;

    // B now sends on ITS current session — the one A has just displaced.
    let reply = next_message(&b, &a, &b_current, "second from B");

    // The single-slot behaviour, asserted so this test cannot pass vacuously.
    assert!(
        decrypt(&a, std::slice::from_ref(&a_current), &reply.envelope_b64).is_err(),
        "if the current session alone could read this, the collision would never have been a \
         defect and this test would be proving nothing",
    );

    // With the displaced session offered too it decrypts, and names the session to promote.
    let candidates: Vec<String> = std::iter::once(a_current)
        .chain(a_archive.iter().cloned())
        .collect();
    let recovered = decrypt(&a, &candidates, &reply.envelope_b64).expect("archive rescues it");
    assert_eq!(body_of(&recovered.payload.inner), "second from B");
    assert_eq!(
        recovered.used_session.as_deref(),
        Some(a_archive[0].as_str()),
        "the caller must be told WHICH session worked; without that it keeps the wrong one current \
         and the two ends never meet",
    );
}

/// The happy path must be untouched: one session, offered alone, keeps working.
#[test]
fn an_ordinary_conversation_uses_the_current_session() {
    let a = party(3);
    let b = party(4);
    let opening = first_message(&a, &b, &b.otks[0], "hello");
    let at_b = decrypt(&b, &[], &opening.envelope_b64).expect("first contact");
    assert_eq!(body_of(&at_b.payload.inner), "hello");
    assert!(at_b.used_session.is_none(), "first contact builds the session");

    let second = next_message(&a, &b, &opening.new_session_blob, "again");
    let at_b2 = decrypt(&b, std::slice::from_ref(&at_b.new_session_blob), &second.envelope_b64)
        .expect("established session");
    assert_eq!(body_of(&at_b2.payload.inner), "again");
    assert_eq!(
        at_b2.used_session.as_deref(),
        Some(at_b.new_session_blob.as_str()),
        "an established session must report itself as used, so nothing is promoted needlessly",
    );
}

/// A corrupt archive entry is skipped, not fatal — one bad row must not take the inbound path
/// down for a whole peer.
#[test]
fn a_corrupt_candidate_is_skipped() {
    let a = party(5);
    let b = party(6);
    let opening = first_message(&a, &b, &b.otks[0], "hi");
    let at_b = decrypt(&b, &[], &opening.envelope_b64).expect("first contact");
    let second = next_message(&a, &b, &opening.new_session_blob, "again");

    let candidates = vec!["not-a-pickle".to_string(), at_b.new_session_blob.clone()];
    let out = decrypt(&b, &candidates, &second.envelope_b64).expect("skips the bad entry");
    assert_eq!(body_of(&out.payload.inner), "again");
}

/// The two no-plaintext outcomes stay distinguishable.
///
/// Callers route on the `InboundDecryptError` VARIANT, not on the wording — nothing greps the
/// text. What is worth asserting is that the two cases do not collapse into one message: "a
/// Normal message arrived with no session at all" and "a session existed but its decrypt failed"
/// need different diagnoses, so this asserts on the codes a caller would branch on.
#[test]
fn the_two_no_plaintext_outcomes_stay_distinguishable() {
    let a = party(7);
    let b = party(8);

    // Getting a NORMAL message takes a full round trip. Until a session has received something,
    // Olm keeps emitting PreKey messages — which a peer can decrypt with no session at all, so
    // asserting on "no session" with one of those would prove nothing.
    let opening = first_message(&a, &b, &b.otks[0], "hi");
    let at_b = decrypt(&b, &[], &opening.envelope_b64).expect("first contact");
    let reply = next_message(&b, &a, &at_b.new_session_blob, "hey");
    let at_a = decrypt(&a, std::slice::from_ref(&opening.new_session_blob), &reply.envelope_b64)
        .expect("A reads the reply");
    // A's session has now received, so this one goes out Normal.
    let second = next_message(&a, &b, &at_a.new_session_blob, "again");

    let err = decrypt_err(&b, &[], &second.envelope_b64);
    assert!(
        err.contains("crypto/no-session-for-normal-message"),
        "unexpected wording: {err}",
    );

    // A session B can legitimately unpickle (its own pickle key) but which cannot read this
    // message: B's session onto a THIRD party. A pickle from someone else's key would fail one step
    // earlier, at unpickling, and would test the wrong branch.
    let other = party(9);
    let wrong = first_message(&b, &other, &other.otks[0], "x").new_session_blob;
    let err = decrypt_err(&b, &[wrong], &second.envelope_b64);
    assert!(err.contains("normal decrypt:"), "unexpected wording: {err}");
}
