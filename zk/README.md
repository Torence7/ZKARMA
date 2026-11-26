# zk/: zkage, ZKARMA's wrapper around Longfellow ZK

`zkage` is a small command-line tool around Google's
[Longfellow ZK](https://github.com/google/longfellow-zk) (its Rust
implementation, frozen **v1** protocol, ZK-spec version 7). The website
verifies with it and the wallet proves with it:

- **website**: `website/proofs.py` already calls `zkage verify` (no changes needed)
- **wallet**: `client/zkage.py` calls `zkage prove`

A proof shows that an mDL signed by the given issuer key has the requested
attributes (e.g. `age_over_18 == true`), is valid at `now`, and was presented
with a device signature over `transcript`. Nothing else about the holder is revealed.

## Build (once per machine)

Needs only [rustup](https://rustup.rs). `rust-toolchain.toml` pins Rust
1.99.0 and rustup installs it automatically. No CMake, OpenSSL or Docker.

```bash
cd zk
cargo build --release                                # ~1 min the first time
target/release/zkage circuits --out circuits-1attr.bin  # 480 KB, 1-attribute circuit
```

Run cargo from inside `zk/`: rustup picks the toolchain and cargo picks up
`.cargo/config.toml` based on the current directory, not `--manifest-path`.
From the repo root you get the system Rust, which fails on older versions.

These are the paths `website/proofs.py` and `client/zkage.py` look for by
default; override them with `ZKAGE_BIN` / `ZKAGE_CIRCUITS`. Both outputs are
gitignored.

`.cargo/config.toml` builds for the local CPU (`target-cpu=native`), which
makes proving about 7× faster. To build a binary for a different machine, set
`RUSTFLAGS=""`.

## Interface

JSON request on stdin; one JSON line on stdout with `"ok": true|false`. Any
failure, including bad input or a crash inside Longfellow, prints `"ok": false`
with an `"error"` and exits 1. Callers should fail closed.

Fields shared by `prove` and `verify` (both sides must use identical values):

| field            | example                                                   |
| ---------------- | --------------------------------------------------------- |
| `issuer_pkx/pky` | `"0x2c80…"`: the issuer's P-256 public key, hex           |
| `transcript_hex` | the session transcript the device key signs               |
| `attributes`     | `[{"namespace": "org.iso.18013.5.1", "id": "age_over_18", "cbor_value_hex": "f5"}]` |
| `now`            | `"2026-11-19T14:00:00Z"`                                  |
| `doc_type`       | optional, default `"org.iso.18013.5.1.mDL"`              |

```bash
zkage prove  --circuits zk/circuits-1attr.bin   # + "mdoc_hex"  -> {"ok":true,"proof_hex":…,"proof_bytes":…,"prove_ms":…}
zkage verify --circuits zk/circuits-1attr.bin   # + "proof_hex" -> {"ok":true,"verify_ms":…}
```

## Test data

`testdata/` holds three of Longfellow's own test mDLs as ready-made `prove`
requests (regenerate with `cargo run --release --example export_vectors -- testdata`):

```bash
zk/target/release/zkage prove --circuits zk/circuits-1attr.bin < zk/testdata/plus18_mdoc_0.json
```

`client/tests/test_zkage.py` proves with these and checks the proofs through
the website's real `proofs.verify`, plus tampering cases (other transcript,
flipped proof byte, untrusted issuer, expired, junk).

**Limitation:** each test mDL's device signature covers *its own* fixed
transcript, so these prove only against that transcript, not against a fresh
ZKARMA challenge. The next step is to re-sign the mdoc's DeviceAuth over our
transcript with the device key, using an mDL from the test DMV (PKI issuer).

## Measurements

Times depend heavily on the CPU and its instruction set, so compare only
numbers taken on the same machine with the same build flags.

**Machine:** AMD Ryzen 7 PRO 8840HS laptop (Zen 4, 8 cores / 16 threads), 14 GB
RAM visible to WSL2 (Linux 6.18, Windows host). Relevant CPU features: AES-NI,
PCLMULQDQ, SHA-NI, AVX2, AVX-512, VAES, VPCLMULQDQ. Build: release,
`target-cpu=native`, Rust 1.99.0. Input: `testdata/plus18_mdoc_0.json`, one attribute.

| step   | time    | peak memory | size           |
| ------ | ------- | ----------- | -------------- |
| prove  | ~0.8 s  | ~110 MB     | proof 360 KB   |
| verify | ~0.3 s  | ~52 MB      | circuit 480 KB |

Without `target-cpu=native` (generic x86-64 build), the same machine took
~5.5 s to prove and ~2.2 s to verify.
