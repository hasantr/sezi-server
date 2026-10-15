//! Source guards for `utils::env_text`, included via `#[path]` from `utils.rs`.

/// Every read of a string binding goes through `env_text`. `Env::var` / `Env::secret` throw inside
/// the wasm on a `null` binding — what bare workerd gives for an unset `fromEnvironment` variable —
/// and the request hangs. One direct call is enough to make an unset setting a 500 on a self-host
/// relay, so none may come back (2026-10-15).
#[test]
fn no_string_binding_is_read_past_env_text() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            for (n, line) in src.lines().enumerate() {
                if line.contains(".var(\"") || line.contains(".secret(\"") || line.contains("env.var(") || line.contains("env.secret(") {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "read through utils::env_text instead:\n{}", offenders.join("\n"));
}
