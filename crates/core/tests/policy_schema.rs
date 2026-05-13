//! Guards the committed JSON Schema against drift from the live derive
//! output. Run `cargo run -p installguard -- schema > schemas/installguard-
//! policy.schema.json` to regenerate, or set `INSTALLGUARD_BLESS=1` and
//! re-run this test.

use std::path::PathBuf;

#[test]
fn committed_policy_schema_matches_derive() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/core → workspace root → schemas/...
    let schema_path = manifest
        .join("../../schemas/installguard-policy.schema.json")
        .canonicalize()
        .expect("schema file exists at <workspace>/schemas/installguard-policy.schema.json");

    let live = installguard_core::policy::Policy::json_schema();
    let live_pretty = serde_json::to_string_pretty(&live).unwrap() + "\n";

    if std::env::var_os("INSTALLGUARD_BLESS").is_some() {
        std::fs::write(&schema_path, &live_pretty).unwrap();
        return;
    }

    let committed = std::fs::read_to_string(&schema_path).unwrap();
    assert!(
        committed == live_pretty,
        "schemas/installguard-policy.schema.json is out of date.\n\
         Run `cargo run -p installguard -- schema > schemas/installguard-policy.schema.json`\n\
         or re-run this test with INSTALLGUARD_BLESS=1."
    );
}
