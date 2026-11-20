//! Writes Longfellow's own test mDLs as zkage prove requests, for tests:
//!
//!     cargo run --release --example export_vectors -- testdata
//!
//! Each mdoc's device signature covers its own fixed transcript, so these only
//! prove against that transcript, not a fresh ZKARMA challenge.

use longfellow_zk::mdoc::testcases::{TestDataStatic, PLUS_18_MDOC_0, PLUS_18_MDOC_1, PLUS_18_MDOC_2};
use serde_json::json;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "testdata".into());
    std::fs::create_dir_all(&dir).expect("create output dir");
    let cases: [(&str, &TestDataStatic); 3] = [
        ("plus18_mdoc_0", &PLUS_18_MDOC_0),
        ("plus18_mdoc_1", &PLUS_18_MDOC_1),
        ("plus18_mdoc_2", &PLUS_18_MDOC_2),
    ];
    for (name, t) in cases {
        let request = json!({
            "mdoc_hex": hex::encode(t.mdoc),
            "issuer_pkx": t.pkx,
            "issuer_pky": t.pky,
            "transcript_hex": hex::encode(t.transcript),
            "attributes": [{"namespace": "org.iso.18013.5.1", "id": "age_over_18", "cbor_value_hex": "f5"}],
            "now": t.now,
            "doc_type": t.doc_type,
        });
        let path = format!("{dir}/{name}.json");
        std::fs::write(&path, serde_json::to_string_pretty(&request).unwrap() + "\n").unwrap();
        println!("wrote {path}");
    }
}
