//! Shared MoLE protocol machinery.
//!
//! This crate implements the pieces of the MoLE drafts that every role needs:
//!
//! * [`wire`] — the TLS 1.3 presentation-language encoding conventions of
//!   draft-jms-mole-http-transport: variable-size (`<V>`) vector length
//!   headers using the QUIC variable-length integer with minimum-size
//!   encoding, and `optional<T>`.
//! * [`messages`] — the protocol messages of draft-jms-mole-http-transport
//!   and draft-jms-mole-protocols, including the type-specific structures for
//!   the IHAT endorsement protocol (type 0x0002) and the ACT credential
//!   protocol (type 0x0001).
//! * [`http`] — the `Mole` HTTP authentication scheme: challenge,
//!   authorization, and `Mole-Credential` header formatting and parsing.
//! * [`config`] — the JSON configuration directories Anchors and Moderators
//!   publish (the concrete form this instantiation gives the drafts'
//!   "Key Rotation and Discovery" section).
//! * [`act`] — glue for the ACT credential mapping: the shared request
//!   context scalar and key identifiers.

pub mod act;
pub mod config;
pub mod http;
pub mod messages;
pub mod wire;

/// MoLE endorsement type values (draft-jms-mole-protocols, IANA section).
pub mod endorsement_type {
    /// Reserved; never on the wire.
    pub const RESERVED: u16 = 0x0000;
    /// The Moderator establishes trust on its own; no Endorsement is redeemed.
    pub const MODERATOR_TRUST: u16 = 0x0001;
    /// IHAT: pairing-free issuer-hiding endorsements over P-256.
    pub const IHAT: u16 = 0x0002;
    /// Longfellow ZK (not implemented here).
    pub const LONGFELLOW: u16 = 0x0003;
}

/// MoLE credential type values (draft-jms-mole-protocols, IANA section).
pub mod credential_type {
    /// Reserved; never on the wire.
    pub const RESERVED: u16 = 0x0000;
    /// Anonymous Credit Tokens.
    pub const ACT: u16 = 0x0001;
    /// Privacy Pass with a reverse flow (not implemented here).
    pub const PRIVACY_PASS_REVERSE: u16 = 0x0002;
    /// Budget Privacy Pass (not implemented here).
    pub const BUDGET_PRIVACY_PASS: u16 = 0x0003;

    /// The reserved greased values, pattern 0x?A?A.
    pub const GREASED: [u16; 16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
        0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ];

    /// Whether a credential type value is one of the reserved greased values.
    /// Real recipients MUST NOT special-case these — this predicate exists for
    /// tests and for the greasing *sender*.
    pub fn is_greased(value: u16) -> bool {
        GREASED.contains(&value)
    }
}

/// The challenge binding of draft-jms-mole-protocols: SHA-256 over the
/// challenge structure in its binary (TLS-presentation) form. Every
/// redemption and presentation is bound to the digest of the challenge that
/// triggered it.
pub fn challenge_digest(challenge_encoding: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(challenge_encoding));
    out
}
