//! zkage: ZKARMA's wrapper around Google's Longfellow ZK.
//!
//! Proves (client) and verifies (website) that an issuer-signed mDL has the
//! requested attributes (e.g. age_over_18 == true), is valid at `now`, and was
//! presented with a device signature over `transcript`. Nothing else leaks.
//!
//! ```text
//! zkage circuits --out FILE [--attributes N]   write the circuit archive once
//! zkage prove    --circuits FILE  < request.json
//! zkage verify   --circuits FILE  < request.json
//! ```
//!
//! Requests are JSON on stdin; the answer is one JSON line on stdout with
//! `"ok": true|false`. See zk/README.md for the fields. Any failure, including
//! a panic inside Longfellow, prints `"ok": false`, so callers fail closed.

use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Instant;

use longfellow_zk::mdoc::v1::{
    provider, req_attr, run_mdoc_prover, run_mdoc_verifier, RequestedAttribute, ZkSpecStruct,
    ZK_SPECS,
};
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
/// Requests are small (a proof is ~360 KB, so ~720 KB as hex); refuse anything huge.
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct Attribute {
    namespace: String,
    id: String,
    /// The attribute's CBOR-encoded value, as hex. CBOR true is "f5".
    cbor_value_hex: String,
}

/// Fields shared by prove and verify. They must be identical on both sides.
#[derive(Deserialize)]
struct Statement {
    issuer_pkx: String,
    issuer_pky: String,
    transcript_hex: String,
    attributes: Vec<Attribute>,
    /// "YYYY-MM-DDTHH:MM:SSZ"
    now: String,
    #[serde(default)]
    doc_type: Option<String>,
}

#[derive(Deserialize)]
struct ProveRequest {
    #[serde(flatten)]
    statement: Statement,
    /// The full mdoc (DeviceResponse) as hex, including the device signature.
    mdoc_hex: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    #[serde(flatten)]
    statement: Statement,
    proof_hex: String,
}

/// The newest frozen v1 spec for this many attributes. ZK_SPECS lists newest first.
fn spec_for(num_attributes: usize) -> Result<&'static ZkSpecStruct, String> {
    ZK_SPECS
        .iter()
        .find(|s| s.num_attributes == num_attributes)
        .ok_or_else(|| format!("no Longfellow v1 circuit for {num_attributes} attribute(s)"))
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.trim_start_matches("0x")).map_err(|e| format!("{field}: bad hex ({e})"))
}

fn attributes(attrs: &[Attribute]) -> Result<Vec<RequestedAttribute>, String> {
    attrs
        .iter()
        .map(|a| {
            let value = decode_hex("cbor_value_hex", &a.cbor_value_hex)?;
            Ok(req_attr(&a.namespace, &a.id, value))
        })
        .collect()
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading stdin: {e}"))?;
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err("request too large".into());
    }
    Ok(buf)
}

fn read_circuits(path: &Option<PathBuf>) -> Result<Vec<u8>, String> {
    let path = path.as_ref().ok_or("--circuits FILE is required")?;
    std::fs::read(path).map_err(|e| format!("reading circuits {}: {e}", path.display()))
}

fn prove(circuits_path: &Option<PathBuf>) -> Result<Value, String> {
    let req: ProveRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("bad request: {e}"))?;
    let circuits = read_circuits(circuits_path)?;
    let st = &req.statement;
    let attrs = attributes(&st.attributes)?;
    let spec = spec_for(attrs.len())?;
    let mdoc = decode_hex("mdoc_hex", &req.mdoc_hex)?;
    let transcript = decode_hex("transcript_hex", &st.transcript_hex)?;
    let doc_type = st.doc_type.as_deref().unwrap_or(DEFAULT_DOC_TYPE);

    let started = Instant::now();
    let proof = run_mdoc_prover(
        spec, &circuits, &mdoc, &st.issuer_pkx, &st.issuer_pky, &transcript, &attrs, &st.now,
        doc_type,
    )
    .map_err(|e| format!("prover: {e:?}"))?;
    Ok(json!({
        "ok": true,
        "proof_hex": hex::encode(&proof),
        "proof_bytes": proof.len(),
        "prove_ms": started.elapsed().as_secs_f64() * 1000.0,
        "zk_spec_version": spec.version,
    }))
}

fn verify(circuits_path: &Option<PathBuf>) -> Result<Value, String> {
    let req: VerifyRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("bad request: {e}"))?;
    let circuits = read_circuits(circuits_path)?;
    let st = &req.statement;
    let attrs = attributes(&st.attributes)?;
    let spec = spec_for(attrs.len())?;
    let proof = decode_hex("proof_hex", &req.proof_hex)?;
    let transcript = decode_hex("transcript_hex", &st.transcript_hex)?;
    let doc_type = st.doc_type.as_deref().unwrap_or(DEFAULT_DOC_TYPE);

    let started = Instant::now();
    run_mdoc_verifier(
        spec, &circuits, &st.issuer_pkx, &st.issuer_pky, &transcript, &attrs, &st.now, doc_type,
        &proof,
    )
    .map_err(|e| format!("verifier: {e:?}"))?;
    Ok(json!({
        "ok": true,
        "verify_ms": started.elapsed().as_secs_f64() * 1000.0,
    }))
}

/// Copies the frozen circuit archive out of Longfellow's source checkout.
fn circuits(out: &Option<PathBuf>, num_attributes: usize) -> Result<Value, String> {
    let out = out.as_ref().ok_or("--out FILE is required")?;
    let spec = spec_for(num_attributes)?;
    let provided = provider::materialize(spec.version, num_attributes)
        .map_err(|e| format!("loading circuit: {e:?}"))?;
    std::fs::write(out, &provided.compressed)
        .map_err(|e| format!("writing {}: {e}", out.display()))?;
    Ok(json!({
        "ok": true,
        "out": out.display().to_string(),
        "bytes": provided.compressed.len(),
        "zk_spec_version": spec.version,
        "num_attributes": num_attributes,
        "circuit_hash": spec.combined_hash_hex(),
    }))
}

const USAGE: &str = "usage:
  zkage circuits --out FILE [--attributes N]
  zkage prove    --circuits FILE  < request.json
  zkage verify   --circuits FILE  < request.json";

fn run(args: Vec<String>) -> Result<Value, String> {
    let mut iter = args.into_iter();
    let command = iter.next().ok_or(USAGE)?;
    let (mut circuits_path, mut out, mut num_attributes) = (None, None, 1usize);
    while let Some(arg) = iter.next() {
        let mut value = || iter.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--circuits" => circuits_path = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--attributes" => {
                num_attributes = value()?.parse().map_err(|_| "--attributes: not a number")?
            }
            _ => return Err(format!("unknown argument {arg}\n{USAGE}")),
        }
    }
    match command.as_str() {
        "prove" => prove(&circuits_path),
        "verify" => verify(&circuits_path),
        "circuits" => circuits(&out, num_attributes),
        "-h" | "--help" | "help" => Err(USAGE.into()),
        _ => Err(format!("unknown command {command}\n{USAGE}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Silence the default panic message; the JSON answer below reports it.
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| run(args)))
        .unwrap_or_else(|_| Err("internal error (panic)".into()));
    let (answer, code) = match result {
        Ok(v) => (v, 0),
        Err(e) => (json!({"ok": false, "error": e}), 1),
    };
    println!("{answer}");
    std::process::exit(code);
}
