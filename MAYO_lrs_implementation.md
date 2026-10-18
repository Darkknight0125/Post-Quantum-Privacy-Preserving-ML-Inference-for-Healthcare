# How the MAYO-scoped linkable ring signature works

This document describes the project implementation in `native/msz_lrs` and
the Python adapter in `src/ppml_healthcare/crypto/mayo_zk_lrs.py`. It explains
the construction and its data flow; it is not a proof that the construction is
anonymous, unforgeable, or post-quantum secure.

## 1. Construction at a glance

The implementation combines three pieces:

1. **MAYO-3** signs an authentication statement with the hospital's MAYO
   signing key.
2. A random 32-byte secret is committed into the hospital's public membership
   row. A hash of that secret and the membership epoch forms the request's
   link tag.
3. **RISC Zero** proves that one hidden row in the ring contains the MAYO
   verification key for a valid signature, and that the same row's commitment
   opens to the secret used to produce the link tag.

The request carries the epoch, link tag, and proof receipt. It does not carry
the selected row index, MAYO public key, MAYO signature, or link secret. The
proof's public journal contains only the epoch and the digests and tag needed
to bind it to the request. This is a project-specific generic ZK construction;
it is not MAYORS, and it is not a native MAYO ring-signature algorithm.

## 2. Mathematical objects

Let the protocol identifier be the byte string
`ppml-healthcare/msz-lrs/v1`. For a byte string `z`, define
`LP(z) = U32BE(|z|) || z`, where `U32BE` is a four-byte unsigned big-endian
integer. Let `H(x) = SHAKE256(x, 32 bytes)`. The implementation uses
domain-separated strings exactly as shown below.

Each member `i` has a MAYO-3 keypair `(pk_i, sk_i)` and an independently
sampled secret `x_i` of 32 bytes. Its public membership row contains:

```text
row_i = "MSZMEM01" || U32BE(|pk_i|) || pk_i || C_i
C_i   = H("MSZ-LRS/member-commit/v1" || LP(protocol_id) || x_i)
```

The hospital's opaque credential contains its MAYO secret key and `x_i`:

```text
credential_i = "MSZKEY01" || U32BE(|sk_i|) || sk_i || x_i
```

The `MSZMEM01` and `MSZKEY01` values are eight-byte format markers. They
version the encodings; they are not hash inputs to `C_i` or the link tag.

### Where MAYO's signature equation fits

MAYO is a multivariate quadratic signature scheme in the Oil-and-Vinegar
family. At a high level its public key describes a quadratic map over a small
finite field. For a message `A`, the implementation's MAYO library derives a
target `t` from the message and salt; a signature vector `sigma` verifies when
the public map evaluates to that target:

```text
P*_pk(sigma) = t(A, salt)
```

The private trapdoor makes finding such a preimage practical for the signer;
finding one from the public map alone is the underlying hard problem. MAYO's
construction modifies the Oil-and-Vinegar map to keep public keys compact.
The MAYO LRS code does not implement this finite-field arithmetic itself: it
calls the `pq-mayo` `Mayo3` signing and verification APIs. This equation is a
high-level signature relation, while the protocol relation below adds hidden
ring membership and link-secret binding. See the [MAYO design overview](https://pqmayo.org/about/)
and [MAYO specification resources](https://pqmayo.org/resources/) for the
primitive's construction and exact parameter-level details.

For epoch `e`, the ordered ring is `R_e = [row_1, ..., row_n]`. The
implementation accepts 2 through 32 rows, sorts by `(pk_i, C_i)`, and rejects
noncanonical order, duplicate public keys, and duplicate commitments. Its
digest is:

```text
rd = H("MSZ-LRS/ring/v1" || LP(protocol_id) || U64BE(e) ||
       U32BE(n) || LP(pk_1) || C_1 || ... || LP(pk_n) || C_n)
```

Here `n` is the number of rows. Since rows are in canonical order, the same
membership snapshot produces the same digest. The epoch is included so that
the digest is tied to the selected snapshot number.

The link tag for member `i` at epoch `e` is:

```text
N_e,i = H("MSZ-LRS/link-tag/v1" || LP(protocol_id) || U64BE(e) || x_i)
```

Thus repeated requests from the same credential in one epoch produce the
same tag. Different random secrets normally produce different tags. Changing
the epoch changes the tag. The tag input does not include the request, ring
digest, or scope; see [linkability scope](#7-linkability-and-scope).

## 3. Binding the proof to a request

The Python client encodes the request authentication core as fixed-order,
length-prefixed binary fields when it has the MAYO adapter's ring digest
operation. The core includes protocol version, epoch, ring digest, request ID,
creation and optional expiry time, model ID/version/hash, KEM ciphertext,
encrypted-feature nonce and ciphertext, and response-correlation bytes. The
proof does not authenticate plaintext patient features: it authenticates the
encrypted request fields that the server receives.

The native code hashes that core and the scope independently:

```text
md = H("MSZ-LRS/request-core/v1" || LP(protocol_id) || LP(request_core))
sd = H("MSZ-LRS/scope/v1" || LP(protocol_id) || LP(scope))
```

The project uses the scope `ppml-healthcare/request-auth/v1`. The message
signed by MAYO-3 is a second, fixed-size statement:

```text
A = "MSZ-LRS/auth-message/v1" || LP(protocol_id) || U64BE(e) || rd || md || sd || N_e,i
sigma_i = MAYO.Sign(sk_i, A)
```

The proof therefore binds the MAYO signature to this epoch, exact ring
snapshot, encrypted request, scope, and tag. A changed request or context
changes the statement and should invalidate verification.

## 4. The zero-knowledge relation

For public statement

```text
P = (e, rd, md, sd, N)
```

the prover supplies private witness

```text
w = (R_e, j, x, sigma)
```

where `j` is a ring index, `x` a 32-byte link secret, and `sigma` a MAYO
signature. The guest accepts exactly when all checks hold:

```text
1. R_e is canonical and has 2 <= |R_e| <= 32.
2. RingDigest(e, R_e) = rd.
3. Commit(x) = commitment(R_e[j]).
4. Tag(e, x) = N.
5. MAYO.Verify(pk(R_e[j]), A(e, rd, md, sd, N), sigma) = true.
```

The same `j` is used for checks 3 and 5. This is the key relation: the secret
behind the public tag and the key that verifies the MAYO signature must belong
to one and the same enrolled row. Proving these checks in one guest execution
is intended to hide `j`, `x`, and `sigma` from the verifier.

On success the guest commits `P` to the RISC Zero journal. It does not commit
the witness or the full ring to the journal. The host verifies the receipt
against the guest image ID and compares its journal with a statement
recomputed from the request and current ring. The ring and witness are inputs
to guest execution, not fields in the Python `RequestEnvelope`.

## 5. Operations in the code

### Enrollment / key generation

`keygen` generates a MAYO-3 keypair and a random `x`, then returns the
encoded public row and credential. The membership service stores the row in
an epoch ring; the hospital protects the credential. The present command
creates both values but does not implement an enrollment authority, proof of
possession workflow, hardware-backed storage, or identity-to-row governance.

### Signing and proving

`sign` decodes the credential and canonical ring, finds the row whose
commitment equals `Commit(x)`, computes `rd`, `md`, `sd`, and `N`, signs `A`
with MAYO-3, and asks RISC Zero to prove the guest relation. It verifies its
own receipt and expected journal before returning the encoded receipt and
32-byte tag. The selected index and MAYO signature exist in prover-side
execution inputs; neither is returned as an explicit request field.

### Verification

`verify` decodes and validates the supplied ring, verifies the receipt for
the pinned guest image, and compares the journal against the epoch, current
ring digest, request digest, scope digest, and supplied tag. Thus a proof for
another ring or request should fail even if its receipt is otherwise valid.
The membership registry and epoch policy remain application responsibilities:
the verifier must be given the authoritative current snapshot, not a
requester's arbitrary ring.

### Linking

The adapter's `link(a, b)` compares the 32-byte tags in constant time. It
returns true only when both signatures also carry equal epoch, ring digest,
and scope metadata. Linking does not rerun proof verification; callers must
verify proofs before relying on a tag. The in-memory rate limiter stores
verified signatures and applies this operation over its sliding window.

## 6. Python/native boundary

The application selects only `MayoScopedZKLRSAdapter`. Python invokes the
native executable with one JSON object on stdin and parses one JSON object on
stdout. Binary fields use standard Base64. The adapter removes
`RISC0_DEV_MODE` from the child environment, applies a subprocess timeout,
and fails closed when the executable is absent or returns malformed output.
The native executable also rejects `RISC0_DEV_MODE`.

The native workspace pins RISC Zero 3.0.6 and `pq-mayo` 0.6.0; the selected
parameter type is `Mayo3`. MAYO signing and verification use the Rust
`pq-mayo` crate. The Python code treats member rows, credentials, and proof
receipts as opaque byte strings.

## 7. Linkability and scope

The protocol has one request-authentication scope today, so the stable
epoch-scoped tag provides the desired repeat-detection input for that flow.
The `scope_digest` is included in the MAYO-signed statement and receipt, and
the Python `link()` method also requires matching scope metadata. However,
because `N` itself is derived from only `(epoch, x)`, the public tag is the
same across scopes within an epoch. An observer who sees tags directly could
therefore correlate them across scopes even though the current adapter's
`link()` method reports false for different scopes. A future design requiring
unlinkability across scopes would need a different tag derivation and matching
proof relation, followed by new analysis and tests.

Similarly, the tag formula includes the epoch but not the ring digest. The
system must treat epoch numbers as globally unique and non-reusable. Reusing
an epoch number for a different ring can cause the same member's tag to recur;
the adapter additionally checks ring digests when linking, but that does not
hide equality of the raw public tag. Epoch uniqueness and privacy across
membership authorities are protocol assumptions, not enforced by the hash.

## 8. Intended properties and limits

Under the intended zero-knowledge behavior, a verifier learns that some row
in the stated ring signed the request and learns the epoch-scoped equality
tag, without learning which row. This is an intended property of the
construction, not a proved claim in this repository. The membership authority
still knows which organization it enrolled; this mechanism does not hide
identity from that authority or prevent it from colluding with the verifier.

The implementation is research code and currently lacks a formal reduction,
independent audit, official MAYO Round 3 KAT comparison, production enrollment
and credential lifecycle, and demonstrated native build on this Windows
host. The RISC Zero proof configuration and serialized receipt must be
independently checked for witness privacy, soundness, and side-channel
behavior. Pinning crate versions alone does not establish those properties.
The use of MAYO does not by itself make the whole construction
post-quantum-secure; the proof system and hash security assumptions also need
analysis. The successful unit tests cover encodings, digest agreement, and
application flow, not anonymity or unforgeability.

Use synthetic data only. Do not describe this implementation as formally
anonymous, uncrackable, production-ready, or a certified post-quantum LRS.

## 9. Relevant code

- `native/msz_lrs/core/src/lib.rs`: encodings, hashes, ring checks, statement.
- `native/msz_lrs/src/main.rs`: key generation, MAYO signing, proving, verify.
- `native/msz_lrs/methods/guest/src/main.rs`: witness relation checked in guest.
- `src/ppml_healthcare/crypto/mayo_zk_lrs.py`: Python adapter and link logic.
- `src/ppml_healthcare/protocol/client.py`: authenticated request core.
- `src/ppml_healthcare/protocol/validation.py`: proof verification in flow.
