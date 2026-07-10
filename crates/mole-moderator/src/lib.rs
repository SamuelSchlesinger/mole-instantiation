//! The MoLE Moderator: challenges Clients, redeems IHAT Endorsements into ACT
//! Credentials, and verifies ACT presentations with updates.
//!
//! Routes:
//!
//! * `GET /.well-known/mole-moderator` — the [`ModeratorDirectory`]
//!   configuration.
//! * `GET /resource` — the protected resource. Unauthenticated requests get a
//!   401 with two `Mole` challenges: the credential challenge (what to
//!   present) and the endorsement challenge (what Redeem & Issue accepts).
//!   `Authorization: Mole credential-request=` runs Redeem & Issue;
//!   `Authorization: Mole presentation=` runs Presentation and Update.
//!
//! Both challenges are deterministic for a policy and epoch, so the Moderator
//! recomputes their digests to check bindings: the IHAT redemption proof is
//! bound to the endorsement challenge digest, and an ACT presentation names
//! the credential challenge digest it answers.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rand_core::OsRng;

use anonymous_credit_tokens::{
    scalar_to_u128, IssuanceRequest as ActLibIssuanceRequest, Params as ActParams,
    PrivateKey as ActPrivateKey, SpendProof,
};
use curve25519_dalek::Scalar;
use ihat::anchor::AnchorPublicKey;
use ihat::{Params as IhatParams, Presentation as IhatLibPresentation, WireFormat};

use mole_core::config::{ModeratorDirectory, ModeratorPolicy, MODERATOR_DIRECTORY_PATH};
use mole_core::http::{
    b64_encode, MoleAuthorization, MoleChallenge, MoleCredential, MOLE_CREDENTIAL,
};
use mole_core::messages::{
    ActChallenge, ActIssuanceRequest, ActIssuanceResponse, ActPresentationAndUpdate, ActUpdate,
    CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
    CredentialUpdate, IhatChallenge, IhatPresentation, ModeratorChallenge,
    OptionalCredentialUpdate,
};
use mole_core::wire::Wire;
use mole_core::{challenge_digest, credential_type, endorsement_type};

/// The protected resource path.
pub const RESOURCE_PATH: &str = "/resource";
/// The protected resource body served on success.
pub const RESOURCE_BODY: &str = "the protected resource\n";

/// Everything that defines a Moderator policy instance.
pub struct ModeratorConfig {
    /// Identifies this policy in challenges and directories.
    pub policy_context: Vec<u8>,
    /// Accepted Anchor keys (SEC1 compressed), in normative order.
    pub accepted_anchor_keys: Vec<[u8; 33]>,
    /// The endorsement context (epoch) accepted for redemption.
    pub endorsement_context: Vec<u8>,
    /// Credits granted at Redeem & Issue.
    pub initial_credits: u64,
    /// The charge (spend amount) of each presentation.
    pub charge: u64,
    /// The partial refund returned with each update, in `[0, charge]`.
    /// This is the dynamic rate-limiting lever: `refund = charge` sustains
    /// access indefinitely, `refund = 0` burns the initial grant down.
    pub refund: u64,
    /// The ACT domain separator for this deployment.
    pub act_domain_separator: Vec<u8>,
}

/// The Moderator's state.
pub struct ModeratorState {
    config: ModeratorConfig,
    ihat_params: IhatParams,
    accepted: Vec<AnchorPublicKey>,
    act_params: ActParams,
    act_key: ActPrivateKey,
    act_key_id: [u8; 32],
    act_ctx: Scalar,
    /// Redeemed IHAT nullifiers for the current epoch.
    seen_endorsement_nullifiers: Mutex<HashSet<Vec<u8>>>,
    /// Spent ACT nullifiers.
    seen_spend_nullifiers: Mutex<HashSet<[u8; 32]>>,
}

impl ModeratorState {
    /// Build the Moderator: parses the accepted Anchor keys and generates a
    /// fresh ACT key pair.
    pub fn new(config: ModeratorConfig) -> anyhow::Result<Self> {
        let accepted = config
            .accepted_anchor_keys
            .iter()
            .map(|bytes| AnchorPublicKey::from_bytes(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid anchor key: {e}"))?;
        anyhow::ensure!(!accepted.is_empty(), "accepted anchor set must be non-empty");
        anyhow::ensure!(
            config.refund <= config.charge,
            "refund must not exceed charge"
        );

        let act_params = ActParams::from_domain_separator(&config.act_domain_separator);
        let act_key = ActPrivateKey::random(OsRng);
        let act_key_id = mole_core::act::key_id(&act_key.public().to_bytes());
        let act_ctx = mole_core::act::request_context_scalar(
            &config.policy_context,
            &config.endorsement_context,
        );

        Ok(ModeratorState {
            ihat_params: IhatParams::standard(),
            accepted,
            act_params,
            act_key,
            act_key_id,
            act_ctx,
            config,
            seen_endorsement_nullifiers: Mutex::new(HashSet::new()),
            seen_spend_nullifiers: Mutex::new(HashSet::new()),
        })
    }

    /// The deterministic endorsement (Redeem & Issue) challenge.
    pub fn moderator_challenge(&self) -> ModeratorChallenge {
        ModeratorChallenge {
            endorsement_type: endorsement_type::IHAT,
            challenge: IhatChallenge {
                keys: self.config.accepted_anchor_keys.clone(),
            }
            .to_bytes(),
        }
    }

    /// The deterministic credential (Presentation) challenge.
    pub fn credential_challenge(&self) -> CredentialChallenge {
        CredentialChallenge {
            credential_type: credential_type::ACT,
            challenge: ActChallenge {
                policy_context: self.config.policy_context.clone(),
                charge: self.config.charge,
                topup: 0,
            }
            .to_bytes(),
        }
    }

    /// How many Endorsement nullifiers have been redeemed this epoch.
    /// Observability for tests and operators.
    pub fn endorsement_nullifier_count(&self) -> usize {
        self.seen_endorsement_nullifiers.lock().unwrap().len()
    }

    /// How many ACT spend nullifiers have been recorded.
    pub fn spend_nullifier_count(&self) -> usize {
        self.seen_spend_nullifiers.lock().unwrap().len()
    }

    fn directory(&self) -> ModeratorDirectory {
        ModeratorDirectory {
            policies: vec![ModeratorPolicy {
                policy_context: b64_encode(&self.config.policy_context),
                credential_type: credential_type::ACT,
                act_public_key: b64_encode(&self.act_key.public().to_bytes()),
                act_domain_separator: b64_encode(&self.config.act_domain_separator),
                initial_credits: self.config.initial_credits,
                charge: self.config.charge,
                endorsement_type: endorsement_type::IHAT,
                accepted_anchor_keys: self
                    .config
                    .accepted_anchor_keys
                    .iter()
                    .map(|k| b64_encode(k))
                    .collect(),
                endorsement_context: b64_encode(&self.config.endorsement_context),
            }],
        }
    }
}

/// Build the Moderator's router.
pub fn router(state: Arc<ModeratorState>) -> Router {
    Router::new()
        .route(MODERATOR_DIRECTORY_PATH, get(directory))
        .route(RESOURCE_PATH, get(resource))
        .with_state(state)
}

async fn directory(State(state): State<Arc<ModeratorState>>) -> impl IntoResponse {
    Json(state.directory())
}

/// 401 with the two `Mole` challenges. Sent when the request carries no
/// recognizable MoLE material (including unknown or greased credential
/// types, which are indistinguishable from absent authentication).
fn challenge_response(state: &ModeratorState, extra: Option<(header::HeaderName, String)>) -> Response {
    let credential = MoleChallenge {
        challenge: state.credential_challenge().to_bytes(),
        realm: Some("moderator".into()),
    };
    let endorsement = MoleChallenge {
        challenge: state.moderator_challenge().to_bytes(),
        realm: Some("moderator".into()),
    };
    let mut builder = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, credential.to_header_value())
        .header(header::WWW_AUTHENTICATE, endorsement.to_header_value());
    if let Some((name, value)) = extra {
        builder = builder.header(name, value);
    }
    builder.body("credential required\n".into()).unwrap()
}

/// 403: the MoLE material was understood but rejected under policy. The
/// body is deliberately uniform — distinguishing "bad proof" from "spent
/// nullifier" is a side channel (drafts, security considerations).
fn reject() -> Response {
    (StatusCode::FORBIDDEN, "rejected\n").into_response()
}

async fn resource(State(state): State<Arc<ModeratorState>>, headers: HeaderMap) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(MoleAuthorization::parse);

    match auth {
        None | Some(Err(_)) => challenge_response(&state, None),
        Some(Ok(MoleAuthorization::CredentialRequest(bytes))) => redeem_and_issue(&state, &bytes),
        Some(Ok(MoleAuthorization::Presentation(bytes))) => present(&state, &bytes),
    }
}

/// Redeem & Issue: verify the endorsement redemption, spend its nullifier,
/// and issue an ACT Credential. On success the response is still a 401 with
/// the unchanged challenges — the Client holds a Credential now but has not
/// yet presented it — carrying the `CredentialResponse` in `Mole-Credential`.
fn redeem_and_issue(state: &ModeratorState, bytes: &[u8]) -> Response {
    let Ok(request) = CredentialRequest::from_bytes(bytes) else {
        return reject();
    };
    // Unknown types are ignored, not errors: answer as if unauthenticated.
    if request.endorsement_type != endorsement_type::IHAT
        || request.credential_type != credential_type::ACT
    {
        return challenge_response(state, None);
    }

    // --- Redeem: verify the IHAT presentation. ---
    let Ok(presentation) = IhatPresentation::from_bytes(&request.endorsement_presentation) else {
        return reject();
    };
    let Ok(presentation) = IhatLibPresentation::from_bytes(&presentation.bytes) else {
        return reject();
    };
    // The redemption is bound to the endorsement challenge that triggered it.
    let binding = challenge_digest(&state.moderator_challenge().to_bytes());
    if !presentation.verify(&state.ihat_params, &state.accepted, &binding) {
        return reject();
    }
    // The Endorsement must be granted in the current epoch.
    if presentation.endorsement.endorsement_context != state.config.endorsement_context {
        return reject();
    }

    // --- Issue: answer the ACT issuance request. ---
    // Everything is validated before the nullifier is recorded, so a
    // rejected request (malformed issuance, stale key id) never spends the
    // Client's Endorsement.
    let Ok(issuance) = ActIssuanceRequest::from_bytes(&request.issuance_request) else {
        return reject();
    };
    if issuance.truncated_key_id != state.act_key_id[31] {
        return reject();
    }
    let Ok(act_request) = ActLibIssuanceRequest::from_bytes(&issuance.request) else {
        return reject();
    };
    let Ok(response) = state.act_key.issue(
        &state.act_params,
        &act_request,
        u128::from(state.config.initial_credits),
        state.act_ctx,
        OsRng,
    ) else {
        return reject();
    };

    // Recording the nullifier spends the Endorsement; it is the last check,
    // and the issued response is released only if this insert wins.
    {
        let mut seen = state.seen_endorsement_nullifiers.lock().unwrap();
        if !seen.insert(presentation.endorsement.nf.clone()) {
            return reject();
        }
    }

    let credential_response = CredentialResponse {
        credential_type: credential_type::ACT,
        issuance_response: ActIssuanceResponse {
            response: response.to_bytes(),
        }
        .to_bytes(),
    };
    challenge_response(
        state,
        Some((
            header::HeaderName::from_static(MOLE_CREDENTIAL),
            MoleCredential::Response(credential_response.to_bytes()).to_header_value(),
        )),
    )
}

/// Presentation and Update: verify the ACT spend against the challenged
/// predicate, spend its nullifier, serve the resource, and return the refund
/// as the update.
fn present(state: &ModeratorState, bytes: &[u8]) -> Response {
    let Ok(presentation) = CredentialPresentation::from_bytes(bytes) else {
        return reject();
    };
    // Unknown and greased credential types are handled exactly alike: ignored.
    if presentation.credential_type != credential_type::ACT {
        return challenge_response(state, None);
    }
    let Ok(pau) = ActPresentationAndUpdate::from_bytes(&presentation.presentation_and_update)
    else {
        return reject();
    };

    // The presentation must answer this policy's current challenge and key.
    let expected_digest = challenge_digest(&state.credential_challenge().to_bytes());
    if pau.challenge_digest != expected_digest || pau.key_id != state.act_key_id {
        return reject();
    }

    let Ok(spend) = SpendProof::from_bytes(&pau.spend_proof) else {
        return reject();
    };
    // The spend's public amounts must match the challenged predicate, and the
    // token must be bound to this policy's request context.
    if scalar_to_u128(&spend.charge()) != Some(u128::from(state.config.charge))
        || scalar_to_u128(&spend.topup()) != Some(0)
        || spend.context() != state.act_ctx
    {
        return reject();
    }

    // `refund` verifies the spend proof; the nullifier check is ours.
    let Ok(refund) = state.act_key.refund(
        &state.act_params,
        &spend,
        u128::from(state.config.refund),
        OsRng,
    ) else {
        return reject();
    };
    {
        let mut seen = state.seen_spend_nullifiers.lock().unwrap();
        if !seen.insert(spend.nullifier().to_bytes()) {
            return reject();
        }
    }

    let update = OptionalCredentialUpdate {
        update: Some(CredentialUpdate {
            credential_type: credential_type::ACT,
            update_response: ActUpdate {
                refund: refund.to_bytes(),
            }
            .to_bytes(),
        }),
    };
    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static(MOLE_CREDENTIAL),
            MoleCredential::Update(update.to_bytes()).to_header_value(),
        )],
        RESOURCE_BODY,
    )
        .into_response()
}
