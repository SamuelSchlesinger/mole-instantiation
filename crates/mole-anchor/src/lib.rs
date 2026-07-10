//! The MoLE Anchor: grants IHAT Endorsements (endorsement type 0x0002).
//!
//! Routes:
//!
//! * `GET /.well-known/mole-anchor` — the [`AnchorDirectory`] configuration.
//! * `POST /mole/endorse` — the grant endpoint. Both IHAT exchanges arrive
//!   here as `application/mole-endorsement-request` bodies; the step-tagged
//!   grant body distinguishes them, and an Anchor-issued session identifier
//!   correlates the second exchange with the state kept from the first.
//!
//! The Anchor endorses according to its own criteria. This instantiation
//! stands trust establishment in for with an `X-Demo-User` header and caps
//! grants per user per epoch, exercising the architecture's requirement that
//! Anchors constrain how many Endorsements a given user receives.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand_core::{OsRng, RngCore};

use ihat::anchor::{AnchorNeedsProofRequest, AnchorSecretKey};
use ihat::{Params, ProofRequest, SignatureRequest, WireFormat};
use mole_core::config::{AnchorDirectory, AnchorEndorsementConfig, ANCHOR_DIRECTORY_PATH};
use mole_core::http::{b64_encode, ENDORSEMENT_REQUEST_MEDIA_TYPE, ENDORSEMENT_RESPONSE_MEDIA_TYPE};
use mole_core::messages::{
    EndorsementRequest, EndorsementResponse, IhatGrantRequest, IhatGrantResponse,
};
use mole_core::wire::Wire;
use mole_core::endorsement_type;

/// How many Endorsements one user may be granted per epoch.
pub const DEFAULT_GRANTS_PER_EPOCH: u32 = 8;

/// The grant endpoint path.
pub const ENDORSE_PATH: &str = "/mole/endorse";

/// The Anchor's state.
pub struct AnchorState {
    params: Params,
    key: AnchorSecretKey,
    endorsement_context: Vec<u8>,
    grants_per_epoch: u32,
    /// Pending second exchanges, keyed by session id.
    sessions: Mutex<HashMap<Vec<u8>, AnchorNeedsProofRequest>>,
    /// Grants issued per user this epoch.
    grants: Mutex<HashMap<String, u32>>,
}

impl AnchorState {
    /// A fresh Anchor with a random key operating in `endorsement_context`.
    pub fn new(endorsement_context: Vec<u8>, grants_per_epoch: u32) -> Self {
        AnchorState {
            params: Params::standard(),
            key: AnchorSecretKey::random(&mut OsRng),
            endorsement_context,
            grants_per_epoch,
            sessions: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
        }
    }

    /// The Anchor's public key, SEC1 compressed.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key
            .public_key(&self.params)
            .to_bytes()
            .expect("anchor public key encodes")
    }

    fn directory(&self) -> AnchorDirectory {
        AnchorDirectory {
            endorsement_configs: vec![AnchorEndorsementConfig {
                endorsement_type: endorsement_type::IHAT,
                public_key: b64_encode(&self.public_key_bytes()),
                endorsement_context: b64_encode(&self.endorsement_context),
                endorse_endpoint: ENDORSE_PATH.to_string(),
            }],
        }
    }
}

/// Build the Anchor's router.
pub fn router(state: Arc<AnchorState>) -> Router {
    Router::new()
        .route(ANCHOR_DIRECTORY_PATH, get(directory))
        .route(ENDORSE_PATH, post(endorse))
        .with_state(state)
}

async fn directory(State(state): State<Arc<AnchorState>>) -> impl IntoResponse {
    Json(state.directory())
}

/// An error response: a status code and a short diagnostic body. Grant errors
/// are 4xx; the body is intentionally coarse.
fn err(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

async fn endorse(
    State(state): State<Arc<AnchorState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some(ENDORSEMENT_REQUEST_MEDIA_TYPE)
    {
        return err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "wrong media type");
    }

    let Ok(request) = EndorsementRequest::from_bytes(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed EndorsementRequest");
    };
    // A recipient that does not recognize the type ignores the message.
    if request.endorsement_type != endorsement_type::IHAT {
        return err(StatusCode::NOT_FOUND, "unknown endorsement type");
    }
    let Ok(grant) = IhatGrantRequest::from_bytes(&request.body) else {
        return err(StatusCode::BAD_REQUEST, "malformed grant body");
    };

    let response_body = match grant {
        IhatGrantRequest::Step1 { signature_request } => {
            // Trust establishment stand-in: the demo user header. A real
            // Anchor grants against a login, payment, or other relationship.
            let Some(user) = headers.get("x-demo-user").and_then(|v| v.to_str().ok()) else {
                return err(StatusCode::UNAUTHORIZED, "no trust relationship");
            };
            {
                let mut grants = state.grants.lock().unwrap();
                let count = grants.entry(user.to_string()).or_insert(0);
                if *count >= state.grants_per_epoch {
                    return err(StatusCode::TOO_MANY_REQUESTS, "grant limit reached");
                }
                *count += 1;
            }

            let Ok(sig_request) = SignatureRequest::from_bytes(&signature_request) else {
                return err(StatusCode::BAD_REQUEST, "malformed SignatureRequest");
            };
            // The Anchor signs only under its own current context; anything
            // else would let a Client move an Endorsement across epochs.
            if sig_request.endorsement_context != state.endorsement_context {
                return err(StatusCode::BAD_REQUEST, "wrong endorsement context");
            }

            let (signature, pending) = sig_request.sign(&state.params, &state.key, &mut OsRng);
            let mut session_id = vec![0u8; 16];
            OsRng.fill_bytes(&mut session_id);
            state
                .sessions
                .lock()
                .unwrap()
                .insert(session_id.clone(), pending);

            IhatGrantResponse::Step1 {
                session_id,
                signature: signature.to_bytes().expect("signature encodes"),
            }
        }
        IhatGrantRequest::Step2 {
            session_id,
            proof_request,
        } => {
            let Some(pending) = state.sessions.lock().unwrap().remove(&session_id) else {
                return err(StatusCode::BAD_REQUEST, "unknown or spent session");
            };
            let Ok(proof_request) = ProofRequest::from_bytes(&proof_request) else {
                return err(StatusCode::BAD_REQUEST, "malformed ProofRequest");
            };
            let proof = pending.prove(proof_request);
            IhatGrantResponse::Step2 {
                proof: proof.to_bytes().expect("proof encodes"),
            }
        }
    };

    let response = EndorsementResponse {
        endorsement_type: endorsement_type::IHAT,
        body: response_body.to_bytes(),
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, ENDORSEMENT_RESPONSE_MEDIA_TYPE)],
        response.to_bytes(),
    )
        .into_response()
}
