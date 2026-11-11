//! `tools/bots/api_v1.json` — the bot API v1, machine-readable — as the tests read it, and the
//! one shape rule they hold a built answer or update to. Test-only: the relay serves nothing from
//! this file; it is the contract the code and `tools/bots/API_V1.md` are both checked against
//! (`conformance_tests.rs`, `inbox_do/bot/updates_tests.rs`).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SPEC_JSON: &str = include_str!("../../../tools/bots/api_v1.json");

pub(crate) fn spec() -> Value {
    serde_json::from_str(SPEC_JSON).expect("tools/bots/api_v1.json is JSON")
}

/// A spec's `{"path": "type", "path?": "type"}` map: each path, whether it may be absent, and
/// its type.
pub(crate) fn fields(map: &Value) -> BTreeMap<String, (bool, String)> {
    map.as_object()
        .expect("a field map")
        .iter()
        .map(|(k, t)| {
            let (path, optional) = match k.strip_suffix('?') {
                Some(p) => (p.to_string(), true),
                None => (k.clone(), false),
            };
            (path, (optional, t.as_str().expect("a type").to_string()))
        })
        .collect()
}

/// Does `v` have JSON type `ty` (`string`, `int`, `bool`, `object`, `array`, `null`, or `a|b`)?
pub(crate) fn has_type(v: &Value, ty: &str) -> bool {
    ty.split('|').any(|t| match t {
        "string" => v.is_string(),
        "int" => v.is_i64() || v.is_u64(),
        "bool" => v.is_boolean(),
        "object" => v.is_object(),
        "array" => v.is_array(),
        "null" => v.is_null(),
        other => panic!("unknown type {other:?} in api_v1.json"),
    })
}

/// Every leaf path of `v`, descending into an object unless the spec names that path itself (it
/// is then one field, `who: object`), and into an array's elements as `name[]` when the spec
/// describes them (`files[].file_id`).
fn leaves(v: &Value, prefix: &str, spec: &BTreeMap<String, (bool, String)>, out: &mut BTreeMap<String, Value>) {
    let Value::Object(map) = v else { return };
    for (k, child) in map {
        let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        let described_below = |p: &str| spec.keys().any(|s| s.starts_with(&format!("{p}.")));
        match child {
            Value::Object(_) if !spec.contains_key(&path) && described_below(&path) => {
                leaves(child, &path, spec, out)
            }
            Value::Array(items) if described_below(&format!("{path}[]")) => {
                for item in items {
                    leaves(item, &format!("{path}[]"), spec, out);
                }
            }
            _ => {
                out.insert(path, child.clone());
            }
        }
    }
}

/// `value` holds to the spec's field map: every path it carries is documented with its type, and
/// every documented path not marked `?` is there. The error names what drifted.
pub(crate) fn check_shape(what: &str, value: &Value, spec_map: &Value) -> Result<(), String> {
    let spec = fields(spec_map);
    let mut got = BTreeMap::new();
    leaves(value, "", &spec, &mut got);
    for (path, v) in &got {
        let Some((_, ty)) = spec.get(path) else {
            return Err(format!("{what}: `{path}` is answered but not documented in api_v1.json"));
        };
        if !has_type(v, ty) {
            return Err(format!("{what}: `{path}` is {v} but documented as {ty}"));
        }
    }
    let present: BTreeSet<&String> = got.keys().collect();
    for (path, (optional, _)) in &spec {
        if !optional && !present.contains(path) {
            return Err(format!("{what}: documented `{path}` is missing"));
        }
    }
    Ok(())
}

/// The spec's list `key` (`methods`, `updates`, `errors`, `features`) as its entries.
pub(crate) fn list(key: &str) -> Vec<Value> {
    spec()[key].as_array().unwrap_or_else(|| panic!("api_v1.json has no {key} list")).clone()
}

#[test]
fn the_shape_rule_finds_drift_both_ways() {
    let spec = serde_json::json!({ "a": "int", "b.c": "string|null", "d?": "object", "f[].x": "int" });
    let ok = serde_json::json!({ "a": 1, "b": { "c": null }, "d": { "anything": 1 }, "f": [{ "x": 2 }] });
    assert_eq!(check_shape("t", &ok, &spec), Ok(()));
    let extra = serde_json::json!({ "a": 1, "b": { "c": "s", "e": 1 }, "f": [] });
    assert!(check_shape("t", &extra, &spec).unwrap_err().contains("`b.e` is answered but not documented"));
    let missing = serde_json::json!({ "b": { "c": "s" } });
    assert!(check_shape("t", &missing, &spec).unwrap_err().contains("`a` is missing"));
    let wrong = serde_json::json!({ "a": "1", "b": { "c": "s" } });
    assert!(check_shape("t", &wrong, &spec).unwrap_err().contains("documented as int"));
}
