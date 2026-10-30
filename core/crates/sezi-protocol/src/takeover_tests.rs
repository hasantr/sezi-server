use super::*;

#[test]
fn a_code_is_six_digits_and_names_one_request() {
    let (_, otk) = new_one_time_key();
    let code = takeover_code("req-1", &otk);
    assert_eq!(code.len(), CODE_DIGITS);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(code, takeover_code("req-1", &otk), "deterministic: the relay derives the same");
    // Another request or another key, another code (with overwhelming probability; these are fixed).
    assert_ne!(takeover_code("req-2", &otk), code);
    let (_, other) = new_one_time_key();
    assert_ne!(takeover_code("req-1", &other), code);
}

#[test]
fn the_separator_keeps_split_points_apart() {
    assert_ne!(takeover_code("ab", "c"), takeover_code("a", "bc"));
}

#[test]
fn a_typed_code_may_carry_spaces_and_dashes_and_nothing_else() {
    let (_, otk) = new_one_time_key();
    let code = takeover_code("r", &otk);
    let spaced = format!("{} {}", &code[..3], &code[3..]);
    let dashed = format!("{}-{}", &code[..3], &code[3..]);
    assert!(code_matches("r", &otk, &code));
    assert!(code_matches("r", &otk, &spaced));
    assert!(code_matches("r", &otk, &dashed));
    assert!(!code_matches("r", &otk, &code[..5]), "five digits are not the code");
    assert!(!code_matches("r", &otk, &format!("{code}0")));
    assert!(!code_matches("r", &otk, ""));
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    assert!(!code_matches("r", &otk, &wrong));
}

#[test]
fn the_release_box_opens_with_the_one_time_secret_only() {
    let (secret, public) = new_one_time_key();
    let sealed = seal_to_one_time_key(&public, b"the share").unwrap();
    assert_eq!(open_with_one_time_key(&secret, &sealed).unwrap(), b"the share");

    let (other, _) = new_one_time_key();
    assert!(open_with_one_time_key(&other, &sealed).is_err(), "another device's key opens nothing");
}

#[test]
fn a_box_changed_on_the_way_does_not_open() {
    let (secret, public) = new_one_time_key();
    let sealed = seal_to_one_time_key(&public, b"the share").unwrap();
    let mut bytes = vodozemac::base64_decode(&sealed).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(open_with_one_time_key(&secret, &vodozemac::base64_encode(&bytes)).is_err());
    // The ephemeral half is bound too: swapping it breaks the tag.
    let mut swapped = vodozemac::base64_decode(&sealed).unwrap();
    let (_, other_pub) = new_one_time_key();
    swapped[..32].copy_from_slice(&vodozemac::base64_decode(&other_pub).unwrap());
    assert!(open_with_one_time_key(&secret, &vodozemac::base64_encode(&swapped)).is_err());
    assert!(open_with_one_time_key(&secret, "c2hvcnQ").is_err(), "too short");
}

#[test]
fn two_seals_of_the_same_share_differ() {
    let (_, public) = new_one_time_key();
    assert_ne!(seal_to_one_time_key(&public, b"x").unwrap(), seal_to_one_time_key(&public, b"x").unwrap());
}

#[test]
fn a_released_share_round_trips_through_json() {
    let share = ReleasedShare { escrow_id: "e1".into(), r_b64: "cg".into() };
    let json = serde_json::to_vec(&share).unwrap();
    assert_eq!(serde_json::from_slice::<ReleasedShare>(&json).unwrap(), share);
}

#[test]
fn a_malformed_one_time_key_is_refused_before_sealing() {
    assert!(seal_to_one_time_key("not base64!", b"x").is_err());
    assert!(seal_to_one_time_key("c2hvcnQ", b"x").is_err());
}
