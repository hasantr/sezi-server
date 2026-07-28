use super::*;

/// Is the hand-maintained MIGRATIONS list in sync with the migrations/ directory?
/// (Add a file and forget the list, and this test breaks.)
#[test]
fn the_migrations_list_matches_the_folder() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .expect("could not read the migrations folder")
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter_map(|n| n.strip_suffix(".sql").map(str::to_string))
        .collect();
    files.sort();
    let names: Vec<String> = MIGRATIONS.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(
        names, files,
        "migrations/*.sql and the MIGRATIONS list disagree — did you add a migration file without adding its line to the list?"
    );
    // Ordering and uniqueness (the file name is the version key).
    for w in names.windows(2) {
        assert!(w[0] < w[1], "MIGRATIONS is out of order: {} >= {}", w[0], w[1]);
    }
}

/// Every embedded file must yield at least one statement, and no statement may carry
/// leftover comment text (the splitter must have stripped it).
#[test]
fn every_migration_can_be_split() {
    for (name, sql) in MIGRATIONS {
        let stmts = split_sql_statements(sql);
        assert!(!stmts.is_empty(), "{name}: no statement came out at all");
        for s in &stmts {
            assert!(!s.trim().is_empty(), "{name}: empty statement");
            assert!(
                !s.contains("--"),
                "{name}: comment residue left inside the statement: {s}"
            );
        }
    }
}

/// The real trap case: an inline comment inside 0014's CREATE TABLE contains a `;`, and a
/// naive split would cut the table in half. The splitter must produce 2 statements
/// (CREATE TABLE + CREATE INDEX) with the CREATE TABLE left intact.
#[test]
fn a_semicolon_inside_a_comment_does_not_end_a_statement() {
    let sql = MIGRATIONS
        .iter()
        .find(|(n, _)| *n == "0014_device_link")
        .unwrap()
        .1;
    let stmts = split_sql_statements(sql);
    assert_eq!(stmts.len(), 2, "0014: expected CREATE TABLE + CREATE INDEX");
    assert!(stmts[0].contains("expires_at") && stmts[0].contains("link_code"));
    assert!(stmts[1].starts_with("CREATE INDEX"));
}

#[test]
fn splitter_handles_string_literals_and_block_comments() {
    let sql = "INSERT INTO t VALUES ('a;b', 'it''s'); /* a comment; with one inside */ SELECT 1;\n-- trailing comment\n";
    let stmts = split_sql_statements(sql);
    assert_eq!(stmts.len(), 2);
    assert_eq!(stmts[0], "INSERT INTO t VALUES ('a;b', 'it''s')");
    assert_eq!(stmts[1], "SELECT 1");
}

/// The single-batch order contract: file1's statements → file1's track → file2's
/// statements → file2's track... A comment-only file yields nothing but its track.
#[test]
fn single_batch_merge_order() {
    let pending: [(&str, &str); 3] = [
        (
            "0001_a",
            "CREATE TABLE a (id INTEGER); CREATE INDEX ia ON a(id);",
        ),
        ("0002_b", "-- comment only, no statement\n"),
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

/// No pending files → empty vector. run_migrations already returns early in that case,
/// but the pure function's contract should be explicit too.
#[test]
fn single_batch_with_nothing_pending_returns_empty() {
    assert!(merge_pending_statements(&[]).is_empty());
}

/// Integrity over the real embedded list: the merged length equals total statements plus
/// one track per file, and each file's track comes AFTER its own statements — exactly the
/// fresh-fork first-boot scenario.
#[test]
fn single_batch_emits_stmt_plus_track_for_every_migration() {
    let pending: Vec<(&str, &str)> = MIGRATIONS.to_vec();
    let merged = merge_pending_statements(&pending);
    let stmt_toplam: usize = MIGRATIONS
        .iter()
        .map(|(_, sql)| split_sql_statements(sql).len())
        .sum();
    assert_eq!(merged.len(), stmt_toplam + MIGRATIONS.len());
    // Track order equals MIGRATIONS order; the last item is the last file's track.
    let tracks: Vec<&String> = merged
        .iter()
        .filter_map(|m| match m {
            MergedStmt::Track(n) => Some(n),
            MergedStmt::Sql(_) => None,
        })
        .collect();
    let expected: Vec<String> = MIGRATIONS.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(tracks, expected.iter().collect::<Vec<_>>());
    assert_eq!(
        merged.last(),
        Some(&MergedStmt::Track(MIGRATIONS.last().unwrap().0.to_string()))
    );
}

#[test]
fn benign_classification() {
    // Benign: re-running a bare ALTER, and re-running a CREATE without IF NOT EXISTS.
    assert!(is_benign_schema_conflict(
        "D1_ERROR: duplicate column name: role: SQLITE_ERROR"
    ));
    assert!(is_benign_schema_conflict(
        "table link_requests already exists"
    ));
    assert!(is_benign_schema_conflict(
        "index idx_link_requests_expiry already exists"
    ));
    // Real errors are NOT swallowed.
    assert!(!is_benign_schema_conflict("no such table: users"));
    assert!(!is_benign_schema_conflict(
        "UNIQUE constraint failed: users.email"
    ));
    assert!(!is_benign_schema_conflict("near \"CREATTE\": syntax error"));
}

#[test]
fn wrangler_name_normalization() {
    assert_eq!(normalize_migration_name("0001_init.sql"), "0001_init");
    assert_eq!(normalize_migration_name("0001_init"), "0001_init");
    assert_eq!(
        normalize_migration_name(" 0025_server_config.sql "),
        "0025_server_config"
    );
}

/// The generated PEM must be BIT-COMPATIBLE with the parser jwt.rs uses for env secrets —
/// the same function, `parse_signing_pem`, which is the proof of format agreement — and it
/// must survive a signature round-trip.
#[test]
fn jwt_pem_roundtrip_is_compatible_with_the_jwt_parser() {
    use ed25519_dalek::{Signer, Verifier};
    let pem = generate_jwt_signing_pem().unwrap();
    // A PEM with real newlines: jwt.rs's `\\n`→`\n` replacement must be a no-op.
    assert!(pem.contains('\n') && !pem.contains("\\n"));
    let key = crate::auth::jwt::parse_signing_pem(&pem).expect("the jwt.rs parser must accept it");
    let msg = b"sezi self-provision roundtrip";
    let sig = key.sign(msg);
    key.verifying_key().verify(msg, &sig).unwrap();
}

#[test]
fn invite_key_generation_is_32_bytes_b64u() {
    let k = generate_admin_invite_key().unwrap();
    // 32 bytes → 43 characters of unpadded b64url.
    assert_eq!(k.len(), 43);
    assert!(crate::utils::b64u_decode(&k).unwrap().len() == 32);
}

/// The self-heal gate (the 2026-07-06 sezi-server2 incident): a corrupt D1 record must NOT
/// pass validate — that is what routes it to regeneration — while a freshly generated key
/// MUST pass, so keys are used after verification instead of blindly.
#[test]
fn validate_jwt_pem_rejects_a_corrupt_record_and_accepts_a_fresh_one() {
    // Field-like corruptions: empty, not a PEM at all, a PEM with a garbage body, a
    // truncated PEM.
    assert!(!validate_jwt_pem(""));
    assert!(!validate_jwt_pem("not a PEM at all"));
    assert!(!validate_jwt_pem(
        "-----BEGIN PRIVATE KEY-----\nQk9aVUsgS0FZSVQ=\n-----END PRIVATE KEY-----\n"
    ));
    let pem = generate_jwt_signing_pem().unwrap();
    let truncated = &pem[..pem.len() / 2];
    assert!(!validate_jwt_pem(truncated));
    // A freshly generated key passes (generator ↔ validator agreement).
    assert!(validate_jwt_pem(&pem));
    // A wrangler-secret style PEM with escaped newlines passes too (the parser replaces them).
    assert!(validate_jwt_pem(&pem.replace('\n', "\\n")));
}

#[test]
fn validate_invite_key_rejects_empty_and_accepts_a_fresh_one() {
    assert!(!validate_invite_key(""));
    assert!(!validate_invite_key("   \n\t"));
    assert!(validate_invite_key(&generate_admin_invite_key().unwrap()));
}
