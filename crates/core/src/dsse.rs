//! DSSE (Dead Simple Signing Envelope) v1 producer and verifier,
//! deliberately compatible with the cosign / sigstore-bundle wire
//! format for Ed25519 keys.
//!
//! This is the keyfile half of Sigstore: no Fulcio, no Rekor, no OIDC,
//! no network — just a raw Ed25519 keypair signing a payload. Cosign
//! verifies the resulting envelope with `cosign verify-blob` when
//! given the matching PEM public key, so InstallGuard signatures slot
//! into existing Sigstore tooling without surprises.
//!
//! Wire format (DSSE v1, <https://github.com/secure-systems-lab/dsse>):
//!
//! ```jsonc
//! {
//!   "payloadType": "application/vnd.in-toto+json",
//!   "payload":     "<base64(payload bytes)>",
//!   "signatures": [
//!     { "keyid": "<sha256(spki DER)>", "sig": "<base64(sig)>" }
//!   ]
//! }
//! ```
//!
//! PAE (Pre-Authentication Encoding) is exactly:
//!
//! ```text
//! "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
//! ```
//!
//! Bytes-for-bytes compatible with cosign's `--key cosign.key`
//! signing path.
//!
//! Key persistence is **PKCS#8 PEM** (`BEGIN PRIVATE KEY` / `BEGIN
//! PUBLIC KEY`), which both `cosign` and `openssl pkey -text` parse.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Standard `payloadType` for in-toto Statements wrapped in DSSE.
/// Exactly the value cosign uses for its `attest --predicate` payloads.
pub const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// DSSE v1 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 (standard, padded) of the raw payload bytes.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// SHA-256 of the SubjectPublicKeyInfo DER, hex-encoded. Matches
    /// the `keyid` cosign records by default for a key it manages.
    pub keyid: String,
    /// Base64 (standard, padded) of the raw signature bytes.
    pub sig: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DsseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("pkcs8: {0}")]
    Pkcs8(String),
    #[error("invalid signature")]
    BadSignature,
    #[error("no signatures present")]
    NoSignatures,
    #[error("payloadType mismatch: expected {expected}, got {actual}")]
    PayloadType { expected: String, actual: String },
    #[error("payload digest mismatch: envelope payload does not match expected bytes")]
    PayloadMismatch,
}

impl From<ed25519_dalek::pkcs8::Error> for DsseError {
    fn from(e: ed25519_dalek::pkcs8::Error) -> Self {
        Self::Pkcs8(e.to_string())
    }
}

impl From<ed25519_dalek::pkcs8::spki::Error> for DsseError {
    fn from(e: ed25519_dalek::pkcs8::spki::Error) -> Self {
        Self::Pkcs8(e.to_string())
    }
}

/// Generate a fresh Ed25519 keypair and write PKCS#8-PEM key files at
/// `priv_path` / `pub_path`. Mirrors the on-disk format cosign uses
/// for its locally-managed keys.
pub fn generate_keypair(
    priv_path: &std::path::Path,
    pub_path: &std::path::Path,
) -> Result<(), DsseError> {
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let priv_pem = signing
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| DsseError::Pkcs8(e.to_string()))?;
    let pub_pem = signing
        .verifying_key()
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?;
    std::fs::write(priv_path, priv_pem.as_bytes())?;
    std::fs::write(pub_path, pub_pem.as_bytes())?;
    Ok(())
}

/// Sign `payload` (raw bytes) with the Ed25519 PKCS#8-PEM key at
/// `priv_path` and return a complete DSSE envelope.
pub fn sign(
    payload: &[u8],
    payload_type: &str,
    priv_path: &std::path::Path,
) -> Result<DsseEnvelope, DsseError> {
    let pem = std::fs::read_to_string(priv_path)?;
    let signing = SigningKey::from_pkcs8_pem(&pem)?;
    let pae = pae(payload_type, payload);
    let sig: Signature = signing.sign(&pae);
    let keyid = keyid_for(&signing.verifying_key())?;
    Ok(DsseEnvelope {
        payload_type: payload_type.to_string(),
        payload: B64.encode(payload),
        signatures: vec![DsseSignature {
            keyid,
            sig: B64.encode(sig.to_bytes()),
        }],
    })
}

/// Verify a DSSE envelope against a public key (Ed25519 PKCS#8 PEM).
/// Returns `Ok(payload_bytes)` if any signature in the envelope is
/// valid under `pub_path` and (when `expected_payload` is `Some`) the
/// envelope payload matches the expected bytes exactly.
pub fn verify(
    env: &DsseEnvelope,
    pub_path: &std::path::Path,
    expected_payload_type: Option<&str>,
    expected_payload: Option<&[u8]>,
) -> Result<Vec<u8>, DsseError> {
    if env.signatures.is_empty() {
        return Err(DsseError::NoSignatures);
    }
    if let Some(t) = expected_payload_type {
        if env.payload_type != t {
            return Err(DsseError::PayloadType {
                expected: t.to_string(),
                actual: env.payload_type.clone(),
            });
        }
    }
    let payload_bytes = B64.decode(env.payload.as_bytes())?;
    if let Some(expected) = expected_payload {
        if expected != payload_bytes.as_slice() {
            return Err(DsseError::PayloadMismatch);
        }
    }
    let pem = std::fs::read_to_string(pub_path)?;
    let verifying = VerifyingKey::from_public_key_pem(&pem)?;
    let pae = pae(&env.payload_type, &payload_bytes);
    for sig in &env.signatures {
        let sig_bytes = B64.decode(sig.sig.as_bytes())?;
        let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            continue;
        };
        let signature = Signature::from_bytes(&arr);
        if verifying.verify(&pae, &signature).is_ok() {
            return Ok(payload_bytes);
        }
    }
    Err(DsseError::BadSignature)
}

/// Pre-Authentication Encoding (DSSE v1).
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

fn keyid_for(vk: &VerifyingKey) -> Result<String, DsseError> {
    let der = vk.to_public_key_der()?;
    let mut h = Sha256::new();
    h.update(der.as_bytes());
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ig-dsse-{}-{name}", std::process::id()))
    }

    #[test]
    fn pae_matches_dsse_spec() {
        // Spec example: type="http://example.com/HelloWorld",
        // payload="hello world".
        let p = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            std::str::from_utf8(&p).unwrap(),
            "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn round_trip_sign_then_verify() {
        let priv_p = tmp("priv.pem");
        let pub_p = tmp("pub.pem");
        let _ = std::fs::remove_file(&priv_p);
        let _ = std::fs::remove_file(&pub_p);
        generate_keypair(&priv_p, &pub_p).unwrap();

        let payload = br#"{"hello":"world"}"#;
        let env = sign(payload, INTOTO_PAYLOAD_TYPE, &priv_p).unwrap();
        assert_eq!(env.payload_type, INTOTO_PAYLOAD_TYPE);
        assert_eq!(env.signatures.len(), 1);

        let got = verify(&env, &pub_p, Some(INTOTO_PAYLOAD_TYPE), Some(payload)).unwrap();
        assert_eq!(got, payload);

        std::fs::remove_file(&priv_p).unwrap();
        std::fs::remove_file(&pub_p).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let priv_p = tmp("priv2.pem");
        let pub_p = tmp("pub2.pem");
        let _ = std::fs::remove_file(&priv_p);
        let _ = std::fs::remove_file(&pub_p);
        generate_keypair(&priv_p, &pub_p).unwrap();

        let mut env = sign(b"original", INTOTO_PAYLOAD_TYPE, &priv_p).unwrap();
        env.payload = B64.encode(b"tampered");
        let err = verify(&env, &pub_p, None, None).unwrap_err();
        assert!(matches!(err, DsseError::BadSignature));

        std::fs::remove_file(&priv_p).unwrap();
        std::fs::remove_file(&pub_p).unwrap();
    }

    #[test]
    fn verify_rejects_payload_mismatch() {
        let priv_p = tmp("priv3.pem");
        let pub_p = tmp("pub3.pem");
        let _ = std::fs::remove_file(&priv_p);
        let _ = std::fs::remove_file(&pub_p);
        generate_keypair(&priv_p, &pub_p).unwrap();

        let env = sign(b"a", INTOTO_PAYLOAD_TYPE, &priv_p).unwrap();
        let err = verify(&env, &pub_p, Some(INTOTO_PAYLOAD_TYPE), Some(b"b")).unwrap_err();
        assert!(matches!(err, DsseError::PayloadMismatch));

        std::fs::remove_file(&priv_p).unwrap();
        std::fs::remove_file(&pub_p).unwrap();
    }

    #[test]
    fn keyid_is_stable_for_a_key() {
        let priv_p = tmp("priv4.pem");
        let pub_p = tmp("pub4.pem");
        let _ = std::fs::remove_file(&priv_p);
        let _ = std::fs::remove_file(&pub_p);
        generate_keypair(&priv_p, &pub_p).unwrap();
        let a = sign(b"x", INTOTO_PAYLOAD_TYPE, &priv_p).unwrap();
        let b = sign(b"y", INTOTO_PAYLOAD_TYPE, &priv_p).unwrap();
        assert_eq!(a.signatures[0].keyid, b.signatures[0].keyid);
        std::fs::remove_file(&priv_p).unwrap();
        std::fs::remove_file(&pub_p).unwrap();
    }
}
