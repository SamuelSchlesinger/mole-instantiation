//! The MoLE protocol messages.
//!
//! The transport-level structures come from draft-jms-mole-http-transport and
//! draft-jms-mole-protocols. The `Ihat*` structures refine the opaque bodies
//! for endorsement type 0x0002 and the `Act*` structures for credential type
//! 0x0001; where the drafts leave contents undefined (the ACT challenge, the
//! grant session correlation) the definitions here are the ones this
//! instantiation proposes — see the practicalities notes in the
//! internet-drafts repository.

use crate::wire::{
    get_fixed, get_opaque_v, get_optional, get_u16, get_u64, get_u8, put_opaque_v, put_optional,
    put_u16, put_u64, put_u8, Wire, WireError,
};

macro_rules! wire_struct {
    (
        $(#[$meta:meta])*
        struct $name:ident {
            $($(#[$fmeta:meta])* $field:ident : $kind:tt),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: wire_struct!(@ty $kind),)*
        }

        impl Wire for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                $(wire_struct!(@put out, self.$field, $kind);)*
            }

            fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
                Ok($name {
                    $($field: wire_struct!(@get buf, $kind)?,)*
                })
            }
        }
    };

    (@ty u8) => { u8 };
    (@ty u16) => { u16 };
    (@ty u64) => { u64 };
    (@ty opaque_v) => { Vec<u8> };
    (@ty digest32) => { [u8; 32] };

    (@put $out:ident, $v:expr, u8) => { put_u8($out, $v) };
    (@put $out:ident, $v:expr, u16) => { put_u16($out, $v) };
    (@put $out:ident, $v:expr, u64) => { put_u64($out, $v) };
    (@put $out:ident, $v:expr, opaque_v) => { put_opaque_v($out, &$v) };
    (@put $out:ident, $v:expr, digest32) => { $out.extend_from_slice(&$v) };

    (@get $buf:ident, u8) => { get_u8($buf) };
    (@get $buf:ident, u16) => { get_u16($buf) };
    (@get $buf:ident, u64) => { get_u64($buf) };
    (@get $buf:ident, opaque_v) => { get_opaque_v($buf) };
    (@get $buf:ident, digest32) => { get_fixed::<32>($buf) };
}

// ---------------------------------------------------------------------------
// Transport-level messages (draft-jms-mole-http-transport / -protocols)
// ---------------------------------------------------------------------------

wire_struct! {
    /// Client -> Anchor grant exchange request body
    /// (`application/mole-endorsement-request`).
    struct EndorsementRequest {
        endorsement_type: u16,
        body: opaque_v,
    }
}

wire_struct! {
    /// Anchor -> Client grant exchange response body
    /// (`application/mole-endorsement-response`).
    struct EndorsementResponse {
        endorsement_type: u16,
        body: opaque_v,
    }
}

wire_struct! {
    /// Anchor -> Client challenge (`WWW-Authenticate: Mole`, realm "anchor").
    struct EndorsementChallenge {
        endorsement_type: u16,
        anchor_context: opaque_v,
    }
}

wire_struct! {
    /// Moderator -> Client challenge for Redeem & Issue: names the endorsement
    /// type it accepts, with the type-specific challenge (for IHAT, the
    /// accepted Anchor key set) inside.
    struct ModeratorChallenge {
        endorsement_type: u16,
        challenge: opaque_v,
    }
}

wire_struct! {
    /// Moderator -> Client challenge for Presentation: names the credential
    /// type, with the type-specific challenge (for ACT, the policy context and
    /// charge) inside.
    struct CredentialChallenge {
        credential_type: u16,
        challenge: opaque_v,
    }
}

wire_struct! {
    /// Client -> Moderator, Redeem & Issue
    /// (`Authorization: Mole credential-request=`): an endorsement redemption
    /// together with a credential issuance request.
    struct CredentialRequest {
        endorsement_type: u16,
        endorsement_presentation: opaque_v,
        credential_type: u16,
        issuance_request: opaque_v,
    }
}

wire_struct! {
    /// Moderator -> Client, Redeem & Issue
    /// (`Mole-Credential: response=`).
    struct CredentialResponse {
        credential_type: u16,
        issuance_response: opaque_v,
    }
}

wire_struct! {
    /// Client -> Moderator, Presentation
    /// (`Authorization: Mole presentation=`).
    struct CredentialPresentation {
        credential_type: u16,
        presentation_and_update: opaque_v,
    }
}

wire_struct! {
    /// Moderator -> Client after a presentation
    /// (inside [`OptionalCredentialUpdate`], `Mole-Credential: update=`).
    struct CredentialUpdate {
        credential_type: u16,
        update_response: opaque_v,
    }
}

/// `optional<CredentialUpdate>`: present when the Credential remains usable
/// after presentation, absent when the Moderator intentionally consumes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionalCredentialUpdate {
    pub update: Option<CredentialUpdate>,
}

impl Wire for OptionalCredentialUpdate {
    fn encode(&self, out: &mut Vec<u8>) {
        put_optional(out, &self.update);
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(OptionalCredentialUpdate {
            update: get_optional(buf)?,
        })
    }
}

// ---------------------------------------------------------------------------
// IHAT endorsement protocol (endorsement type 0x0002)
// ---------------------------------------------------------------------------

/// The IHAT `Challenge`: the Anchor public keys the Moderator accepts, in the
/// order published in its configuration (OR-proof branches match keys by
/// position).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IhatChallenge {
    /// SEC1-compressed P-256 points, 33 bytes each.
    pub keys: Vec<[u8; 33]>,
}

impl Wire for IhatChallenge {
    fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(self.keys.len() * 33);
        for key in &self.keys {
            body.extend_from_slice(key);
        }
        put_opaque_v(out, &body);
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let body = get_opaque_v(buf)?;
        if body.len() % 33 != 0 {
            return Err(WireError::Malformed("IHAT key set not a multiple of 33"));
        }
        let keys = body.as_chunks::<33>().0.to_vec();
        Ok(IhatChallenge { keys })
    }
}

wire_struct! {
    /// The IHAT `Presentation`: the output of `Present` (an ihat-rs
    /// `Presentation` in its wire encoding), carried in the
    /// `endorsement_presentation` field of a [`CredentialRequest`].
    struct IhatPresentation {
        bytes: opaque_v,
    }
}

/// The bodies of the two IHAT grant exchanges. The Anchor holds state between
/// them, so the second exchange must be correlated with the first: the Anchor
/// returns an opaque `session_id` in its first response and the Client echoes
/// it in its second request. (The drafts flag this correlation as an open
/// TODO; a session identifier at the endorsement-protocol layer is the
/// resolution this instantiation proposes.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IhatGrantRequest {
    /// First exchange: the ihat-rs `SignatureRequest` wire bytes.
    Step1 { signature_request: Vec<u8> },
    /// Second exchange: the session from step 1 and the ihat-rs
    /// `ProofRequest` wire bytes.
    Step2 {
        session_id: Vec<u8>,
        proof_request: Vec<u8>,
    },
}

impl Wire for IhatGrantRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            IhatGrantRequest::Step1 { signature_request } => {
                put_u8(out, 1);
                put_opaque_v(out, signature_request);
            }
            IhatGrantRequest::Step2 {
                session_id,
                proof_request,
            } => {
                put_u8(out, 2);
                put_opaque_v(out, session_id);
                put_opaque_v(out, proof_request);
            }
        }
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        match get_u8(buf)? {
            1 => Ok(IhatGrantRequest::Step1 {
                signature_request: get_opaque_v(buf)?,
            }),
            2 => Ok(IhatGrantRequest::Step2 {
                session_id: get_opaque_v(buf)?,
                proof_request: get_opaque_v(buf)?,
            }),
            _ => Err(WireError::Malformed("unknown IHAT grant step")),
        }
    }
}

/// The bodies of the two IHAT grant responses, mirroring
/// [`IhatGrantRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IhatGrantResponse {
    /// First exchange: a fresh session identifier and the ihat-rs `Signature`
    /// wire bytes.
    Step1 {
        session_id: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Second exchange: the ihat-rs `Proof` wire bytes.
    Step2 { proof: Vec<u8> },
}

impl Wire for IhatGrantResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            IhatGrantResponse::Step1 {
                session_id,
                signature,
            } => {
                put_u8(out, 1);
                put_opaque_v(out, session_id);
                put_opaque_v(out, signature);
            }
            IhatGrantResponse::Step2 { proof } => {
                put_u8(out, 2);
                put_opaque_v(out, proof);
            }
        }
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        match get_u8(buf)? {
            1 => Ok(IhatGrantResponse::Step1 {
                session_id: get_opaque_v(buf)?,
                signature: get_opaque_v(buf)?,
            }),
            2 => Ok(IhatGrantResponse::Step2 {
                proof: get_opaque_v(buf)?,
            }),
            _ => Err(WireError::Malformed("unknown IHAT grant step")),
        }
    }
}

// ---------------------------------------------------------------------------
// ACT credential protocol (credential type 0x0001)
// ---------------------------------------------------------------------------

wire_struct! {
    /// The ACT `Challenge`. The drafts leave its contents undefined ("must
    /// express the predicate and the charged amount"); this instantiation
    /// defines it as the policy identifier plus the two public amounts of an
    /// ACT spend:
    ///
    /// * `charge` — the amount `s` the Client must prove it can spend. The
    ///   predicate the Moderator learns is "new balance `c - s + a >= 0`".
    /// * `topup` — the Moderator-authorized top-up `a`, normally 0.
    ///
    /// Both amounts are policy-wide constants: varying them per Client would
    /// partition the anonymity set.
    struct ActChallenge {
        policy_context: opaque_v,
        charge: u64,
        topup: u64,
    }
}

wire_struct! {
    /// The ACT `IssuanceRequest` (draft-jms-mole-protocols): a truncated key
    /// identifier and an ACT issuance request message.
    struct ActIssuanceRequest {
        truncated_key_id: u8,
        request: opaque_v,
    }
}

wire_struct! {
    /// The ACT `IssuanceResponse`: an ACT issuance response message.
    struct ActIssuanceResponse {
        response: opaque_v,
    }
}

wire_struct! {
    /// The ACT `PresentationAndUpdate` (draft-jms-mole-protocols): the digest
    /// of the challenge being answered, the full key identifier, and an ACT
    /// spend proof message.
    struct ActPresentationAndUpdate {
        challenge_digest: digest32,
        key_id: digest32,
        spend_proof: opaque_v,
    }
}

wire_struct! {
    /// The ACT `Update`: an ACT refund message. Finalizing it yields the
    /// replacement Credential.
    struct ActUpdate {
        refund: opaque_v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Wire + PartialEq + std::fmt::Debug>(value: &T) {
        let bytes = value.to_bytes();
        let decoded = T::from_bytes(&bytes).expect("decode");
        assert_eq!(&decoded, value);
        assert_eq!(decoded.to_bytes(), bytes, "canonical re-encode");
    }

    #[test]
    fn transport_messages_round_trip() {
        round_trip(&EndorsementRequest {
            endorsement_type: 0x0002,
            body: vec![1, 2, 3],
        });
        round_trip(&ModeratorChallenge {
            endorsement_type: 0x0002,
            challenge: vec![9; 100],
        });
        round_trip(&CredentialChallenge {
            credential_type: 0x0001,
            challenge: vec![],
        });
        round_trip(&CredentialRequest {
            endorsement_type: 0x0002,
            endorsement_presentation: vec![7; 500],
            credential_type: 0x0001,
            issuance_request: vec![8; 130],
        });
        round_trip(&CredentialResponse {
            credential_type: 0x0001,
            issuance_response: vec![4; 162],
        });
        round_trip(&CredentialPresentation {
            credential_type: 0x0001,
            presentation_and_update: vec![5; 700],
        });
        round_trip(&OptionalCredentialUpdate { update: None });
        round_trip(&OptionalCredentialUpdate {
            update: Some(CredentialUpdate {
                credential_type: 0x0001,
                update_response: vec![6; 162],
            }),
        });
    }

    #[test]
    fn ihat_messages_round_trip() {
        round_trip(&IhatChallenge {
            keys: vec![[2u8; 33], [3u8; 33]],
        });
        round_trip(&IhatPresentation { bytes: vec![1; 64] });
        round_trip(&IhatGrantRequest::Step1 {
            signature_request: vec![1, 2],
        });
        round_trip(&IhatGrantRequest::Step2 {
            session_id: vec![0; 16],
            proof_request: vec![3; 32],
        });
        round_trip(&IhatGrantResponse::Step1 {
            session_id: vec![0; 16],
            signature: vec![4; 132],
        });
        round_trip(&IhatGrantResponse::Step2 { proof: vec![5; 96] });
    }

    #[test]
    fn act_messages_round_trip() {
        round_trip(&ActChallenge {
            policy_context: b"policy-1".to_vec(),
            charge: 1,
            topup: 0,
        });
        round_trip(&ActIssuanceRequest {
            truncated_key_id: 0xAB,
            request: vec![1; 130],
        });
        round_trip(&ActIssuanceResponse {
            response: vec![2; 162],
        });
        round_trip(&ActPresentationAndUpdate {
            challenge_digest: [7; 32],
            key_id: [8; 32],
            spend_proof: vec![3; 800],
        });
        round_trip(&ActUpdate {
            refund: vec![4; 162],
        });
    }

    #[test]
    fn malformed_ihat_key_set_rejected() {
        // 34 bytes: not a multiple of 33.
        let mut bytes = Vec::new();
        crate::wire::put_opaque_v(&mut bytes, &[0u8; 34]);
        assert!(IhatChallenge::from_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_grant_step_rejected() {
        assert!(IhatGrantRequest::from_bytes(&[3, 0]).is_err());
    }
}
