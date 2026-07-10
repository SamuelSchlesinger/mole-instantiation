//! Glue for the ACT credential mapping (credential type 0x0001).
//!
//! ACT binds every credit token to a *request context* scalar `ctx` at
//! issuance, and the token's spend proof reveals that scalar. Because it is
//! revealed at every presentation, `ctx` MUST be a policy-wide constant —
//! deriving it from anything per-Client would link presentations back to
//! Redeem & Issue. This instantiation derives it from the policy context and
//! the credential epoch, so every Client under the same policy shares it.

use curve25519_dalek::Scalar;
use sha2::{Digest, Sha512};

/// Domain-separation tag for the request context scalar derivation.
const DST_REQUEST_CONTEXT: &[u8] = b"MoLE-ACT:request-context:v1";

/// Derive the shared ACT request context scalar for a policy.
///
/// `policy_context` identifies the Moderator policy and `epoch` the
/// credential epoch (this instantiation reuses the endorsement context).
/// Uniform via SHA-512 and wide reduction; both fields are length-prefixed so
/// the encoding is injective.
pub fn request_context_scalar(policy_context: &[u8], epoch: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DST_REQUEST_CONTEXT);
    hasher.update((policy_context.len() as u64).to_be_bytes());
    hasher.update(policy_context);
    hasher.update((epoch.len() as u64).to_be_bytes());
    hasher.update(epoch);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The key identifier of an ACT public key: SHA-256 over its 32-byte
/// encoding. Carried in full in `PresentationAndUpdate` and truncated to its
/// final byte in `IssuanceRequest`, following the Privacy Pass convention.
pub fn key_id(public_key_bytes: &[u8]) -> [u8; 32] {
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(b"MoLE-ACT:key-id:v1");
    hasher.update(public_key_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The truncated key identifier: the final byte of [`key_id`].
pub fn truncated_key_id(public_key_bytes: &[u8]) -> u8 {
    key_id(public_key_bytes)[31]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_context_is_deterministic_and_separated() {
        let a = request_context_scalar(b"policy-1", b"epoch-1");
        let b = request_context_scalar(b"policy-1", b"epoch-1");
        assert_eq!(a, b);
        assert_ne!(a, request_context_scalar(b"policy-2", b"epoch-1"));
        assert_ne!(a, request_context_scalar(b"policy-1", b"epoch-2"));
        // Length framing: shifting bytes across the boundary must not collide.
        assert_ne!(
            request_context_scalar(b"policy-1e", b"poch-1"),
            request_context_scalar(b"policy-1", b"epoch-1")
        );
    }

    #[test]
    fn key_id_truncation_is_last_byte() {
        let pk = [7u8; 32];
        assert_eq!(truncated_key_id(&pk), key_id(&pk)[31]);
    }
}
