use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use msz_lrs_core::{
    ProofInput, PublicClaim, Witness, auth_message, decode_member, decode_secret, digest_request,
    digest_ring, digest_scope, encode_member, encode_secret, ring_is_canonical, tag,
};
use msz_lrs_methods::{MSZ_LRS_GUEST_ELF, MSZ_LRS_GUEST_ID};
use pq_mayo::{KeyPair, Mayo3, SigningKey};
use rand::{RngCore, rng};
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};
use serde::{Deserialize, Serialize};
use signature::Signer;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Input {
    Keygen,
    Sign {
        credential: String,
        ring: Vec<String>,
        message: String,
        scope: String,
        epoch: u64,
    },
    Verify {
        proof: String,
        ring: Vec<String>,
        message: String,
        scope: String,
        epoch: u64,
        link_tag: String,
    },
}
#[derive(Serialize)]
struct KeyOutput {
    public_key: String,
    secret_key: String,
}
#[derive(Serialize)]
struct SignatureOutput {
    proof: String,
    link_tag: String,
}
fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(s).context("invalid base64 input")?)
}
fn encode<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}
fn parse_ring(rows: Vec<String>) -> Result<Vec<msz_lrs_core::RingEntry>> {
    let ring = rows
        .iter()
        .map(|r| decode_member(&b64(r)?))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ring_is_canonical(&ring),
        "anonymous ring must have 2..32 unique canonical members"
    );
    Ok(ring)
}
fn run() -> Result<()> {
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "RISC0_DEV_MODE is forbidden"
    );
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let input: Input = serde_json::from_str(&raw)?;
    match input {
        Input::Keygen => {
            let mut r = rng();
            let pair = KeyPair::<Mayo3>::generate(&mut r);
            let mut x = [0u8; 32];
            r.fill_bytes(&mut x);
            let pk = pair.verifying_key().as_ref().to_vec();
            let sk = pair.signing_key().as_ref().to_vec();
            encode(&KeyOutput {
                public_key: STANDARD.encode(encode_member(&pk, &x)),
                secret_key: STANDARD.encode(encode_secret(&sk, &x)),
            })
        }
        Input::Sign {
            credential,
            ring,
            message,
            scope,
            epoch,
        } => {
            let ring = parse_ring(ring)?;
            let (sk, x) = decode_secret(&b64(&credential)?)?;
            let index = ring
                .iter()
                .position(|r| r.commitment == msz_lrs_core::commitment(&x))
                .context("credential is not enrolled in supplied ring")?;
            let rd = digest_ring(epoch, &ring);
            let md = digest_request(&b64(&message)?);
            let sd = digest_scope(&b64(&scope)?);
            let t = tag(epoch, &x);
            let auth = auth_message(epoch, &rd, &md, &sd, &t);
            let signing = SigningKey::<Mayo3>::try_from(sk.as_slice())
                .context("invalid MAYO-3 credential")?;
            let sig = signing.try_sign(&auth).context("MAYO-3 signing failed")?;
            let pi = ProofInput {
                epoch,
                ring,
                ring_digest: rd,
                request_digest: md,
                scope_digest: sd,
                link_tag: t,
                witness: Witness {
                    index: index as u32,
                    link_secret: x,
                    mayo_signature: sig.as_ref().to_vec(),
                },
            };
            let env = ExecutorEnv::builder().write(&pi)?.build()?;
            let receipt = default_prover()
                .prove(env, MSZ_LRS_GUEST_ELF)
                .context("RISC Zero proving failed")?
                .receipt;
            receipt
                .verify(MSZ_LRS_GUEST_ID)
                .context("generated proof did not verify")?;
            let claim: PublicClaim = receipt.journal.decode()?;
            ensure!(
                claim
                    == PublicClaim {
                        epoch,
                        ring_digest: rd,
                        request_digest: md,
                        scope_digest: sd,
                        link_tag: t
                    },
                "proof public claim mismatch"
            );
            let proof = serde_json::to_vec(&receipt).context("serialize proof receipt")?;
            encode(&SignatureOutput {
                proof: STANDARD.encode(proof),
                link_tag: STANDARD.encode(t),
            })
        }
        Input::Verify {
            proof,
            ring,
            message,
            scope,
            epoch,
            link_tag,
        } => {
            let ring = parse_ring(ring)?;
            let receipt: Receipt = serde_json::from_slice(&b64(&proof)?)?;
            receipt
                .verify(MSZ_LRS_GUEST_ID)
                .context("invalid MAYO-scoped LRS proof")?;
            let claim: PublicClaim = receipt.journal.decode()?;
            let expected = PublicClaim {
                epoch,
                ring_digest: digest_ring(epoch, &ring),
                request_digest: digest_request(&b64(&message)?),
                scope_digest: digest_scope(&b64(&scope)?),
                link_tag: b64(&link_tag)?
                    .try_into()
                    .context("link tag must be 32 bytes")?,
            };
            ensure!(
                claim == expected,
                "proof claim does not match current request context"
            );
            encode(&serde_json::json!({"valid":true}))
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
