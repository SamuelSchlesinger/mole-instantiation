//! Configuration directories.
//!
//! The drafts' "Key Rotation and Discovery" section is an open TODO. This
//! instantiation makes it concrete with Privacy Pass-style JSON directories
//! served from well-known paths:
//!
//! * Anchors serve [`AnchorDirectory`] at `/.well-known/mole-anchor`.
//! * Moderators serve [`ModeratorDirectory`] at `/.well-known/mole-moderator`.
//!
//! Byte-valued fields (keys, contexts) are base64url without padding. The
//! order of `accepted_anchor_keys` is normative: IHAT OR-proof branches match
//! keys by position.

use serde::{Deserialize, Serialize};

/// Well-known path for the Anchor directory.
pub const ANCHOR_DIRECTORY_PATH: &str = "/.well-known/mole-anchor";
/// Well-known path for the Moderator directory.
pub const MODERATOR_DIRECTORY_PATH: &str = "/.well-known/mole-moderator";

/// The configuration an Anchor publishes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorDirectory {
    /// One entry per supported endorsement type.
    #[serde(rename = "endorsement-configs")]
    pub endorsement_configs: Vec<AnchorEndorsementConfig>,
}

/// One endorsement type an Anchor supports.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorEndorsementConfig {
    /// The endorsement type (0x0002 for IHAT).
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// The Anchor public key, base64url. For IHAT: a 33-byte SEC1-compressed
    /// P-256 point.
    #[serde(rename = "public-key")]
    pub public_key: String,
    /// The current endorsement context (epoch), base64url. Endorsements are
    /// granted under, and redeemable in, this epoch.
    #[serde(rename = "endorsement-context")]
    pub endorsement_context: String,
    /// Path of the grant endpoint, relative to the directory origin.
    #[serde(rename = "endorse-endpoint")]
    pub endorse_endpoint: String,
}

/// The configuration a Moderator publishes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeratorDirectory {
    /// One entry per policy the Moderator enforces.
    pub policies: Vec<ModeratorPolicy>,
}

/// One Moderator policy: the credential it issues, the Anchors it accepts,
/// and the amounts that define its predicate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeratorPolicy {
    /// Identifies this policy; carried in challenges, base64url.
    #[serde(rename = "policy-context")]
    pub policy_context: String,
    /// The credential type (0x0001 for ACT).
    #[serde(rename = "credential-type")]
    pub credential_type: u16,
    /// The ACT public key (32-byte compressed Ristretto point), base64url.
    #[serde(rename = "act-public-key")]
    pub act_public_key: String,
    /// The ACT domain separator these keys operate under, base64url. Both
    /// sides construct ACT parameters from these exact bytes.
    #[serde(rename = "act-domain-separator")]
    pub act_domain_separator: String,
    /// Credits granted at Redeem & Issue.
    #[serde(rename = "initial-credits")]
    pub initial_credits: u64,
    /// The charge (spend amount `s`) of each presentation under this policy.
    pub charge: u64,
    /// The endorsement type accepted for Redeem & Issue (0x0002 for IHAT).
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// The accepted Anchor keys, base64url, in normative order.
    #[serde(rename = "accepted-anchor-keys")]
    pub accepted_anchor_keys: Vec<String>,
    /// The endorsement context (epoch) accepted for redemption, base64url.
    #[serde(rename = "endorsement-context")]
    pub endorsement_context: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_round_trip_json() {
        let dir = ModeratorDirectory {
            policies: vec![ModeratorPolicy {
                policy_context: "cG9saWN5LTE".into(),
                credential_type: 1,
                act_public_key: "AAAA".into(),
                act_domain_separator: "ZG9tYWlu".into(),
                initial_credits: 10,
                charge: 1,
                endorsement_type: 2,
                accepted_anchor_keys: vec!["AA".into(), "AB".into()],
                endorsement_context: "ZXBvY2gtMQ".into(),
            }],
        };
        let json = serde_json::to_string(&dir).unwrap();
        assert_eq!(serde_json::from_str::<ModeratorDirectory>(&json).unwrap(), dir);

        let anchor = AnchorDirectory {
            endorsement_configs: vec![AnchorEndorsementConfig {
                endorsement_type: 2,
                public_key: "Ag".into(),
                endorsement_context: "ZXBvY2gtMQ".into(),
                endorse_endpoint: "/mole/endorse".into(),
            }],
        };
        let json = serde_json::to_string(&anchor).unwrap();
        assert_eq!(serde_json::from_str::<AnchorDirectory>(&json).unwrap(), anchor);
    }
}
