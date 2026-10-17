use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const PROTOCOL_ID: &[u8] = b"ppml-healthcare/msz-lrs/v1";
pub const MAX_RING_SIZE: usize = 32;
const MEMBER_MAGIC: &[u8] = b"MSZMEM01";
const SECRET_MAGIC: &[u8] = b"MSZKEY01";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingEntry {
    pub public_key: Vec<u8>,
    pub commitment: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub index: u32,
    pub link_secret: [u8; 32],
    pub mayo_signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    pub epoch: u64,
    pub ring: Vec<RingEntry>,
    pub ring_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub scope_digest: [u8; 32],
    pub link_tag: [u8; 32],
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicClaim {
    pub epoch: u64,
    pub ring_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub scope_digest: [u8; 32],
    pub link_tag: [u8; 32],
}

fn shake(input: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(input);
    let mut reader = h.finalize_xof();
    let mut out = [0; 32];
    reader.read(&mut out);
    out
}
fn protocol_prefix() -> Vec<u8> {
    let mut v = (PROTOCOL_ID.len() as u32).to_be_bytes().to_vec();
    v.extend(PROTOCOL_ID);
    v
}
pub fn commitment(x: &[u8; 32]) -> [u8; 32] {
    let mut v = b"MSZ-LRS/member-commit/v1".to_vec();
    v.extend(protocol_prefix());
    v.extend(x);
    shake(&v)
}
pub fn tag(epoch: u64, x: &[u8; 32]) -> [u8; 32] {
    let mut v = b"MSZ-LRS/link-tag/v1".to_vec();
    v.extend(protocol_prefix());
    v.extend(epoch.to_be_bytes());
    v.extend(x);
    shake(&v)
}
pub fn digest_request(message: &[u8]) -> [u8; 32] {
    let mut v = b"MSZ-LRS/request-core/v1".to_vec();
    v.extend(protocol_prefix());
    v.extend((message.len() as u32).to_be_bytes());
    v.extend(message);
    shake(&v)
}
pub fn digest_scope(scope: &[u8]) -> [u8; 32] {
    let mut v = b"MSZ-LRS/scope/v1".to_vec();
    v.extend(protocol_prefix());
    v.extend((scope.len() as u32).to_be_bytes());
    v.extend(scope);
    shake(&v)
}
pub fn encode_member(pk: &[u8], x: &[u8; 32]) -> Vec<u8> {
    let mut o = MEMBER_MAGIC.to_vec();
    o.extend((pk.len() as u32).to_be_bytes());
    o.extend(pk);
    o.extend(commitment(x));
    o
}
pub fn decode_member(raw: &[u8]) -> anyhow::Result<RingEntry> {
    anyhow::ensure!(
        raw.len() >= 44 && raw.starts_with(MEMBER_MAGIC),
        "invalid member row"
    );
    let n = u32::from_be_bytes(raw[8..12].try_into()?) as usize;
    anyhow::ensure!(
        n > 0 && raw.len() == 12 + n + 32,
        "non-canonical member row length"
    );
    Ok(RingEntry {
        public_key: raw[12..12 + n].to_vec(),
        commitment: raw[12 + n..].try_into()?,
    })
}
pub fn encode_secret(sk: &[u8], x: &[u8; 32]) -> Vec<u8> {
    let mut o = SECRET_MAGIC.to_vec();
    o.extend((sk.len() as u32).to_be_bytes());
    o.extend(sk);
    o.extend(x);
    o
}
pub fn decode_secret(raw: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    anyhow::ensure!(
        raw.len() >= 44 && raw.starts_with(SECRET_MAGIC),
        "invalid MAYO credential"
    );
    let n = u32::from_be_bytes(raw[8..12].try_into()?) as usize;
    anyhow::ensure!(
        n > 0 && raw.len() == 12 + n + 32,
        "non-canonical credential length"
    );
    Ok((raw[12..12 + n].to_vec(), raw[12 + n..].try_into()?))
}
pub fn ring_is_canonical(r: &[RingEntry]) -> bool {
    r.len() >= 2
        && r.len() <= MAX_RING_SIZE
        && r.windows(2)
            .all(|w| (&w[0].public_key, &w[0].commitment) < (&w[1].public_key, &w[1].commitment))
        && r.iter().enumerate().all(|(i, a)| {
            r[i + 1..]
                .iter()
                .all(|b| a.public_key != b.public_key && a.commitment != b.commitment)
        })
}
pub fn digest_ring(epoch: u64, r: &[RingEntry]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(b"MSZ-LRS/ring/v1");
    h.update(&(PROTOCOL_ID.len() as u32).to_be_bytes());
    h.update(PROTOCOL_ID);
    h.update(&epoch.to_be_bytes());
    h.update(&(r.len() as u32).to_be_bytes());
    for e in r {
        h.update(&(e.public_key.len() as u32).to_be_bytes());
        h.update(&e.public_key);
        h.update(&e.commitment);
    }
    let mut o = [0; 32];
    h.finalize_xof().read(&mut o);
    o
}
pub fn auth_message(e: u64, r: &[u8; 32], m: &[u8; 32], s: &[u8; 32], t: &[u8; 32]) -> Vec<u8> {
    let mut o = b"MSZ-LRS/auth-message/v1".to_vec();
    o.extend(protocol_prefix());
    o.extend(e.to_be_bytes());
    o.extend(r);
    o.extend(m);
    o.extend(s);
    o.extend(t);
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn member_and_credential_encodings_round_trip() {
        let x = [7u8; 32];
        let pk = b"public-key";
        let row = decode_member(&encode_member(pk, &x)).unwrap();
        let (sk, decoded_x) = decode_secret(&encode_secret(b"secret-key", &x)).unwrap();
        assert_eq!(row.public_key, pk);
        assert_eq!(row.commitment, commitment(&x));
        assert_eq!(sk, b"secret-key");
        assert_eq!(decoded_x, x);
    }
    #[test]
    fn epoch_scope_changes_link_tag() {
        let x = [11u8; 32];
        assert_ne!(tag(1, &x), tag(2, &x));
        assert_eq!(tag(1, &x), tag(1, &x));
    }
    #[test]
    fn ring_order_and_duplicate_keys_are_checked() {
        let a = RingEntry {
            public_key: vec![1],
            commitment: [1; 32],
        };
        let b = RingEntry {
            public_key: vec![2],
            commitment: [2; 32],
        };
        assert!(ring_is_canonical(&[a.clone(), b.clone()]));
        assert!(!ring_is_canonical(&[b, a.clone()]));
        assert!(!ring_is_canonical(&[a.clone(), a]));
    }

    #[test]
    fn ring_digest_matches_python_interop_vector() {
        let rows = [
            RingEntry {
                public_key: vec![1, 2],
                commitment: [3; 32],
            },
            RingEntry {
                public_key: vec![4],
                commitment: [5; 32],
            },
        ];
        assert_eq!(
            hex::encode(digest_ring(7, &rows)),
            "0f7ff6d9ea86c1540449788529796a4b64730ee327c145b04754779b11ba43e8"
        );
    }
}
