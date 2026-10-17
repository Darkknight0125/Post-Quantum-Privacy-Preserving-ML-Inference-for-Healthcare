#![no_main]
use msz_lrs_core::{
    ProofInput, PublicClaim, auth_message, commitment, digest_ring, ring_is_canonical, tag,
};
use pq_mayo::{Mayo3, Signature, VerifyingKey};
use risc0_zkvm::guest::env;
use signature::Verifier;
risc0_zkvm::guest::entry!(main);
fn main() {
    let i: ProofInput = env::read();
    assert!(ring_is_canonical(&i.ring));
    assert_eq!(digest_ring(i.epoch, &i.ring), i.ring_digest);
    let n = i.witness.index as usize;
    assert!(n < i.ring.len());
    let row = &i.ring[n];
    assert_eq!(commitment(&i.witness.link_secret), row.commitment);
    assert_eq!(tag(i.epoch, &i.witness.link_secret), i.link_tag);
    let m = auth_message(
        i.epoch,
        &i.ring_digest,
        &i.request_digest,
        &i.scope_digest,
        &i.link_tag,
    );
    let vk = VerifyingKey::<Mayo3>::try_from(row.public_key.as_slice()).expect("invalid MAYO key");
    let sig = Signature::<Mayo3>::try_from(i.witness.mayo_signature.as_slice())
        .expect("invalid MAYO signature");
    assert!(vk.verify(&m, &sig).is_ok());
    env::commit(&PublicClaim {
        epoch: i.epoch,
        ring_digest: i.ring_digest,
        request_digest: i.request_digest,
        scope_digest: i.scope_digest,
        link_tag: i.link_tag,
    });
}
