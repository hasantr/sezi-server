//! FCM response classification (D-M8): which answers delete a token.

use super::*;

// D-M8: a bare INVALID_ARGUMENT with NO token signal is Transient. A systematic 400
// (our own payload/config bug) must not wipe the token registry — that regression is
// exactly the self-concealing death of push.
#[test]
fn dm8_generic_invalid_argument_not_stale() {
    let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Request contains an invalid argument."}}"#;
    assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Transient);
}

// A payload bug — a field we sent — must not kill the token.
#[test]
fn dm8_payload_field_violation_not_stale() {
    let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Request contains an invalid argument.","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.android.priority","description":"Invalid value"}]}]}}"#;
    assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Transient);
}

// A violation on the token field itself → genuinely stale, so it gets deleted.
#[test]
fn dm8_token_field_violation_is_stale() {
    let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"Invalid registration token"}]}]}}"#;
    assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Stale);
}

// No `details` at all, only "registration token" in the human-readable message → stale.
#[test]
fn dm8_registration_token_message_is_stale() {
    let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token"}}"#;
    assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Stale);
}

// Empty or malformed body → conservatively KEEP the token (Transient).
#[test]
fn dm8_unparseable_body_not_stale() {
    assert_eq!(classify_fcm_send(400, ""), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(400, "{corrupt json"), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(404, ""), FcmSendOutcome::Transient);
}

// 404 UNREGISTERED → stale; 200 → sent.
#[test]
fn dm8_unregistered_stale_and_200_sent() {
    let body = r#"{"error":{"code":404,"status":"NOT_FOUND","message":"Requested entity was not found.","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
    assert_eq!(classify_fcm_send(404, body), FcmSendOutcome::Stale);
    assert_eq!(classify_fcm_send(200, ""), FcmSendOutcome::Sent);
    assert_eq!(classify_fcm_send(200, "anything"), FcmSendOutcome::Sent);
    // 5xx → Transient.
    assert_eq!(classify_fcm_send(503, "unavailable"), FcmSendOutcome::Transient);
}

// ---- K8: which answers mean "these credentials can never reach this token" ----

/// FCM's real shape for a token another project minted: 403 PERMISSION_DENIED carrying the
/// `FcmError` code SENDER_ID_MISMATCH.
const SENDER_ID_MISMATCH_BODY: &str = r#"{"error":{"code":403,"message":"SenderId mismatch","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"SENDER_ID_MISMATCH"}]}}"#;

#[test]
fn k8_sender_id_mismatch_is_recognised() {
    assert_eq!(classify_fcm_send(403, SENDER_ID_MISMATCH_BODY), FcmSendOutcome::SenderMismatch);
}

/// A 403 about the CREDENTIALS (the API disabled, a missing role) is not about the token: it
/// stays transient. So does a 401.
#[test]
fn k8_other_403s_stay_transient() {
    let api_disabled = r#"{"error":{"code":403,"message":"Firebase Cloud Messaging API has not been used in project 1 before or it is disabled.","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]}}"#;
    let no_role = r#"{"error":{"code":403,"message":"Permission 'cloudmessaging.messages.create' denied on resource","status":"PERMISSION_DENIED"}}"#;
    let third_party = r#"{"error":{"code":401,"status":"UNAUTHENTICATED","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"THIRD_PARTY_AUTH_ERROR"}]}}"#;
    assert_eq!(classify_fcm_send(403, api_disabled), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(403, no_role), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(401, third_party), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(403, ""), FcmSendOutcome::Transient);
}

/// The code is read from the structured details, never from prose: a message that merely
/// mentions it is not the signal.
#[test]
fn k8_the_code_must_be_structured() {
    let prose = r#"{"error":{"code":403,"message":"SENDER_ID_MISMATCH?","status":"PERMISSION_DENIED"}}"#;
    assert_eq!(classify_fcm_send(403, prose), FcmSendOutcome::Transient);
    assert_eq!(classify_fcm_send(403, "SENDER_ID_MISMATCH"), FcmSendOutcome::Transient);
}

/// Server errors stay transient.
#[test]
fn k8_5xx_stays_transient() {
    let body = r#"{"error":{"code":503,"status":"UNAVAILABLE"}}"#;
    for code in [500, 502, 503] {
        assert_eq!(classify_fcm_send(code, body), FcmSendOutcome::Transient);
    }
}
