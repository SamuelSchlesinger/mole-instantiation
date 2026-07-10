//! The MoLE Client: drives the full flow against an Anchor and a Moderator.
//!
//! Given a protected resource URL, [`MoleClient::fetch`]:
//!
//! 1. requests the resource; on a 401 it parses the `Mole` challenges;
//! 2. if it holds no Credential for the policy, obtains an IHAT Endorsement
//!    from its Anchor (the two-exchange grant) and redeems it at the
//!    Moderator for an ACT Credential (Redeem & Issue);
//! 3. presents the Credential against the challenged predicate, spending it,
//!    and finalizes the returned update into its replacement.
//!
//! Credentials are burned before their presentation is sent (the architecture
//! requires a Credential never be offered in two contexts), and a fresh
//! Endorsement is never redeemed twice.

use std::collections::HashMap;

use anonymous_credit_tokens::{
    CreditToken, IssuanceResponse as ActLibIssuanceResponse, Params as ActParams, PreIssuance,
    PublicKey as ActPublicKey, Refund, scalar_to_u128,
};
use rand_core::{OsRng, RngCore};

use ihat::anchor::AnchorPublicKey;
use ihat::client::{ClientNeedsSignature, IssuedEndorsement};
use ihat::{Params as IhatParams, Proof, Signature, WireFormat};

use mole_core::config::{
    AnchorDirectory, ModeratorDirectory, ModeratorPolicy, ANCHOR_DIRECTORY_PATH,
    MODERATOR_DIRECTORY_PATH,
};
use mole_core::http::{
    b64_decode, parse_challenges, MoleAuthorization, MoleCredential,
    ENDORSEMENT_REQUEST_MEDIA_TYPE, MOLE_CREDENTIAL,
};
use mole_core::messages::{
    ActChallenge, ActIssuanceRequest, ActIssuanceResponse, ActPresentationAndUpdate, ActUpdate,
    CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
    CredentialUpdate, EndorsementRequest, EndorsementResponse, IhatChallenge, IhatGrantRequest,
    IhatGrantResponse, IhatPresentation, ModeratorChallenge, OptionalCredentialUpdate,
};
use mole_core::wire::Wire;
use mole_core::{challenge_digest, credential_type, endorsement_type};

/// An error in the Client's flow.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("protocol: {0}")]
    Protocol(String),
}

fn protocol(message: impl Into<String>) -> ClientError {
    ClientError::Protocol(message.into())
}

/// An unredeemed Endorsement together with what redemption needs.
struct StoredEndorsement {
    issued: IssuedEndorsement,
    anchor_key: Vec<u8>,
    endorsement_context: Vec<u8>,
}

/// A usable Credential together with what presentation needs.
struct StoredCredential {
    token: CreditToken,
    act_public_key: ActPublicKey,
    act_params: ActParams,
}

/// Keys Credentials are stored under: the policy context they were issued
/// for.
type PolicyKey = Vec<u8>;

/// The MoLE Client.
pub struct MoleClient {
    http: reqwest::Client,
    ihat_params: IhatParams,
    /// Origin of the Anchor this Client has a trust relationship with.
    anchor_origin: String,
    /// The stand-in trust relationship: the demo username sent to the Anchor.
    demo_user: String,
    endorsements: Vec<StoredEndorsement>,
    credentials: HashMap<PolicyKey, StoredCredential>,
}

/// The outcome of a fetch, for callers that want to observe the flow.
#[derive(Debug, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The resource body.
    pub body: String,
    /// Whether this fetch had to run Redeem & Issue (false when a stored
    /// Credential answered the challenge directly).
    pub redeemed: bool,
}

impl MoleClient {
    /// A Client that gets its Endorsements from the Anchor at `anchor_origin`
    /// and identifies to it as `demo_user`.
    pub fn new(anchor_origin: impl Into<String>, demo_user: impl Into<String>) -> Self {
        MoleClient {
            http: reqwest::Client::new(),
            ihat_params: IhatParams::standard(),
            anchor_origin: anchor_origin.into(),
            demo_user: demo_user.into(),
            endorsements: Vec::new(),
            credentials: HashMap::new(),
        }
    }

    /// Fetch a protected resource, running whatever MoLE flows it takes.
    pub async fn fetch(&mut self, url: &str) -> Result<FetchOutcome, ClientError> {
        let response = self.http.get(url).send().await?;
        if response.status().is_success() {
            return Ok(FetchOutcome {
                body: response.text().await?,
                redeemed: false,
            });
        }
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Err(protocol(format!(
                "unexpected status {}",
                response.status()
            )));
        }

        let (credential_challenge, moderator_challenge) = parse_moderator_challenges(&response)?;
        let act_challenge = ActChallenge::from_bytes(&credential_challenge.challenge)
            .map_err(|e| protocol(format!("malformed ACT challenge: {e}")))?;
        let policy_key = act_challenge.policy_context.clone();

        let mut redeemed = false;
        if !self.credentials.contains_key(&policy_key) {
            self.redeem_and_issue(url, &act_challenge, &moderator_challenge)
                .await?;
            redeemed = true;
        }

        let body = self
            .present(url, &credential_challenge, &act_challenge)
            .await?;
        Ok(FetchOutcome { body, redeemed })
    }

    /// The number of credits the Client believes it holds under a policy.
    pub fn balance(&self, policy_context: &[u8]) -> Option<u64> {
        self.credentials
            .get(policy_context)
            .and_then(|c| scalar_to_u128(&c.token.credits()))
            .and_then(|c| u64::try_from(c).ok())
    }

    // -- Endorsement (grant) --------------------------------------------

    /// Run the two-exchange IHAT grant against the Anchor.
    async fn obtain_endorsement(&mut self) -> Result<(), ClientError> {
        let directory: AnchorDirectory = self
            .http
            .get(format!("{}{}", self.anchor_origin, ANCHOR_DIRECTORY_PATH))
            .send()
            .await?
            .json()
            .await?;
        let config = directory
            .endorsement_configs
            .iter()
            .find(|c| c.endorsement_type == endorsement_type::IHAT)
            .ok_or_else(|| protocol("anchor offers no IHAT config"))?;
        let anchor_key = b64_decode(&config.public_key)
            .map_err(|e| protocol(format!("anchor key encoding: {e}")))?;
        let anchor_public_key = AnchorPublicKey::from_bytes(&anchor_key)
            .map_err(|e| protocol(format!("anchor key: {e}")))?;
        let endorsement_context = b64_decode(&config.endorsement_context)
            .map_err(|e| protocol(format!("endorsement context encoding: {e}")))?;
        let endorse_url = format!("{}{}", self.anchor_origin, config.endorse_endpoint);

        // The nullifier is Client-chosen and never seen by the Anchor.
        let mut nf = [0u8; 32];
        OsRng.fill_bytes(&mut nf);

        // Exchange 1: blinded nullifier out, signature back.
        let (signature_request, pending) = ClientNeedsSignature::request(
            nf.to_vec(),
            endorsement_context.clone(),
            &mut OsRng,
        );
        let response = self
            .grant_exchange(
                &endorse_url,
                IhatGrantRequest::Step1 {
                    signature_request: signature_request
                        .to_bytes()
                        .map_err(|e| protocol(format!("encode: {e}")))?,
                },
            )
            .await?;
        let IhatGrantResponse::Step1 {
            session_id,
            signature,
        } = response
        else {
            return Err(protocol("anchor answered with the wrong grant step"));
        };
        let signature = Signature::from_bytes(&signature)
            .map_err(|e| protocol(format!("malformed Signature: {e}")))?;

        // Exchange 2: twisted challenge out, proof back.
        let (proof_request, pending) =
            pending.request_proof(&self.ihat_params, anchor_public_key, signature);
        let response = self
            .grant_exchange(
                &endorse_url,
                IhatGrantRequest::Step2 {
                    session_id,
                    proof_request: proof_request
                        .to_bytes()
                        .map_err(|e| protocol(format!("encode: {e}")))?,
                },
            )
            .await?;
        let IhatGrantResponse::Step2 { proof } = response else {
            return Err(protocol("anchor answered with the wrong grant step"));
        };
        let proof =
            Proof::from_bytes(&proof).map_err(|e| protocol(format!("malformed Proof: {e}")))?;

        // Finalize locally; on failure the session must be discarded, never
        // retried with the same state.
        let issued = pending
            .finalize(&self.ihat_params, proof)
            .ok_or_else(|| protocol("endorsement finalization failed; session discarded"))?;

        self.endorsements.push(StoredEndorsement {
            issued,
            anchor_key,
            endorsement_context,
        });
        Ok(())
    }

    /// One POST of the grant flow.
    async fn grant_exchange(
        &self,
        endorse_url: &str,
        request: IhatGrantRequest,
    ) -> Result<IhatGrantResponse, ClientError> {
        let body = EndorsementRequest {
            endorsement_type: endorsement_type::IHAT,
            body: request.to_bytes(),
        };
        let response = self
            .http
            .post(endorse_url)
            .header(reqwest::header::CONTENT_TYPE, ENDORSEMENT_REQUEST_MEDIA_TYPE)
            .header("x-demo-user", &self.demo_user)
            .body(body.to_bytes())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(protocol(format!(
                "anchor grant exchange failed: {}",
                response.status()
            )));
        }
        let bytes = response.bytes().await?;
        let response = EndorsementResponse::from_bytes(&bytes)
            .map_err(|e| protocol(format!("malformed EndorsementResponse: {e}")))?;
        if response.endorsement_type != endorsement_type::IHAT {
            return Err(protocol("anchor answered with an unknown endorsement type"));
        }
        IhatGrantResponse::from_bytes(&response.body)
            .map_err(|e| protocol(format!("malformed grant response body: {e}")))
    }

    // -- Redeem & Issue ---------------------------------------------------

    /// Redeem an Endorsement at the Moderator and finalize the ACT Credential
    /// it issues in return.
    async fn redeem_and_issue(
        &mut self,
        url: &str,
        act_challenge: &ActChallenge,
        moderator_challenge: &ModeratorChallenge,
    ) -> Result<(), ClientError> {
        if moderator_challenge.endorsement_type != endorsement_type::IHAT {
            return Err(protocol("moderator does not accept IHAT endorsements"));
        }
        let ihat_challenge = IhatChallenge::from_bytes(&moderator_challenge.challenge)
            .map_err(|e| protocol(format!("malformed IHAT challenge: {e}")))?;

        // The policy configuration: ACT key material and issuance parameters.
        let policy = self.fetch_policy(url, &act_challenge.policy_context).await?;
        let act_public_key_bytes = b64_decode(&policy.act_public_key)
            .map_err(|e| protocol(format!("ACT key encoding: {e}")))?;
        let act_public_key = ActPublicKey::from_bytes(&act_public_key_bytes)
            .map_err(|e| protocol(format!("ACT key: {e:?}")))?;
        let act_params = ActParams::from_domain_separator(
            &b64_decode(&policy.act_domain_separator)
                .map_err(|e| protocol(format!("ACT domain separator encoding: {e}")))?,
        );
        let expected_context = b64_decode(&policy.endorsement_context)
            .map_err(|e| protocol(format!("endorsement context encoding: {e}")))?;

        // Find (or obtain) an Endorsement from an Anchor in the accepted set,
        // granted in the epoch the Moderator accepts.
        let index = match self.usable_endorsement(&ihat_challenge, &expected_context) {
            Some(index) => index,
            None => {
                self.obtain_endorsement().await?;
                self.usable_endorsement(&ihat_challenge, &expected_context)
                    .ok_or_else(|| {
                        protocol("no Anchor in the accepted set will endorse this client")
                    })?
            }
        };
        let endorsement = self.endorsements.swap_remove(index);
        let true_index = ihat_challenge
            .keys
            .iter()
            .position(|k| k[..] == endorsement.anchor_key[..])
            .expect("usable_endorsement checked membership");

        // Redeem: the presentation is bound to the digest of the challenge
        // that triggered it.
        let accepted = ihat_challenge
            .keys
            .iter()
            .map(|k| AnchorPublicKey::from_bytes(k))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| protocol(format!("accepted set key: {e}")))?;
        let binding = challenge_digest(&moderator_challenge.to_bytes());
        let presentation = endorsement
            .issued
            .show(&accepted, true_index, &binding, &mut OsRng);

        // Issue: the ACT issuance request rides along.
        let pre_issuance = PreIssuance::random(OsRng);
        let issuance_request = pre_issuance.request(&act_params, OsRng);
        let request = CredentialRequest {
            endorsement_type: endorsement_type::IHAT,
            endorsement_presentation: IhatPresentation {
                bytes: presentation
                    .to_bytes()
                    .map_err(|e| protocol(format!("encode: {e}")))?,
            }
            .to_bytes(),
            credential_type: credential_type::ACT,
            issuance_request: ActIssuanceRequest {
                truncated_key_id: mole_core::act::truncated_key_id(&act_public_key_bytes),
                request: issuance_request.to_bytes(),
            }
            .to_bytes(),
        };

        let response = self
            .http
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                MoleAuthorization::CredentialRequest(request.to_bytes()).to_header_value(),
            )
            .send()
            .await?;
        // Redemption success still challenges (the Client has not presented
        // yet); the Credential is in the Mole-Credential header.
        let Some(credential_header) = response
            .headers()
            .get(MOLE_CREDENTIAL)
            .and_then(|v| v.to_str().ok())
        else {
            return Err(protocol(format!(
                "redeem & issue rejected: {}",
                response.status()
            )));
        };
        let MoleCredential::Response(response_bytes) = MoleCredential::parse(credential_header)
            .map_err(|e| protocol(format!("Mole-Credential: {e}")))?
        else {
            return Err(protocol("expected a response parameter, got update"));
        };
        let credential_response = CredentialResponse::from_bytes(&response_bytes)
            .map_err(|e| protocol(format!("malformed CredentialResponse: {e}")))?;
        if credential_response.credential_type != credential_type::ACT {
            return Err(protocol("moderator issued an unknown credential type"));
        }
        let issuance_response =
            ActIssuanceResponse::from_bytes(&credential_response.issuance_response)
                .map_err(|e| protocol(format!("malformed ActIssuanceResponse: {e}")))?;
        let act_response = ActLibIssuanceResponse::from_bytes(&issuance_response.response)
            .map_err(|e| protocol(format!("malformed ACT response: {e:?}")))?;

        // Finalize: both sides derive the shared request context scalar.
        let ctx = mole_core::act::request_context_scalar(
            &act_challenge.policy_context,
            &endorsement.endorsement_context,
        );
        let token = pre_issuance
            .to_credit_token(
                &act_params,
                &act_public_key,
                &issuance_request,
                &act_response,
                ctx,
            )
            .map_err(|e| protocol(format!("credential finalization failed: {e:?}")))?;

        self.credentials.insert(
            act_challenge.policy_context.clone(),
            StoredCredential {
                token,
                act_public_key,
                act_params,
            },
        );
        Ok(())
    }

    /// The index of a stored Endorsement usable against this challenge: its
    /// Anchor is in the accepted set and its epoch is the one expected.
    fn usable_endorsement(
        &self,
        challenge: &IhatChallenge,
        expected_context: &[u8],
    ) -> Option<usize> {
        self.endorsements.iter().position(|e| {
            e.endorsement_context == expected_context
                && challenge.keys.iter().any(|k| k[..] == e.anchor_key[..])
        })
    }

    /// Fetch the Moderator's directory entry for a policy.
    async fn fetch_policy(
        &self,
        resource_url: &str,
        policy_context: &[u8],
    ) -> Result<ModeratorPolicy, ClientError> {
        let origin = origin_of(resource_url)?;
        let directory: ModeratorDirectory = self
            .http
            .get(format!("{origin}{MODERATOR_DIRECTORY_PATH}"))
            .send()
            .await?
            .json()
            .await?;
        directory
            .policies
            .into_iter()
            .find(|p| {
                b64_decode(&p.policy_context)
                    .map(|c| c == policy_context)
                    .unwrap_or(false)
            })
            .ok_or_else(|| protocol("moderator directory lacks the challenged policy"))
    }

    // -- Presentation and Update ------------------------------------------

    /// Present the stored Credential against the challenge, finalizing the
    /// update into its replacement.
    async fn present(
        &mut self,
        url: &str,
        credential_challenge: &CredentialChallenge,
        act_challenge: &ActChallenge,
    ) -> Result<String, ClientError> {
        // Burn on use: the Credential leaves the store before the request is
        // sent, and only its update-derived replacement ever returns.
        let credential = self
            .credentials
            .remove(&act_challenge.policy_context)
            .ok_or_else(|| protocol("no credential for this policy"))?;

        let (spend, pre_refund) = credential
            .token
            .prove_spend(
                &credential.act_params,
                u128::from(act_challenge.charge),
                u128::from(act_challenge.topup),
                OsRng,
            )
            .map_err(|e| protocol(format!("spend proof failed (balance too low?): {e:?}")))?;

        let presentation = CredentialPresentation {
            credential_type: credential_type::ACT,
            presentation_and_update: ActPresentationAndUpdate {
                challenge_digest: challenge_digest(&credential_challenge.to_bytes()),
                key_id: mole_core::act::key_id(&credential.act_public_key.to_bytes()),
                spend_proof: spend.to_bytes(),
            }
            .to_bytes(),
        };

        let response = self
            .http
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                MoleAuthorization::Presentation(presentation.to_bytes()).to_header_value(),
            )
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(protocol(format!(
                "presentation rejected: {}",
                response.status()
            )));
        }

        // Finalize the update into the replacement Credential. An absent
        // update means the Moderator consumed the Credential.
        let update_header = response
            .headers()
            .get(MOLE_CREDENTIAL)
            .and_then(|v| v.to_str().ok())
            .map(MoleCredential::parse);
        if let Some(Ok(MoleCredential::Update(update_bytes))) = update_header {
            let update = OptionalCredentialUpdate::from_bytes(&update_bytes)
                .map_err(|e| protocol(format!("malformed update: {e}")))?;
            if let Some(CredentialUpdate {
                credential_type: ct,
                update_response,
            }) = update.update
            {
                if ct == credential_type::ACT {
                    let act_update = ActUpdate::from_bytes(&update_response)
                        .map_err(|e| protocol(format!("malformed ActUpdate: {e}")))?;
                    let refund = Refund::from_bytes(&act_update.refund)
                        .map_err(|e| protocol(format!("malformed Refund: {e:?}")))?;
                    let token = pre_refund
                        .to_credit_token(
                            &credential.act_params,
                            &spend,
                            &refund,
                            &credential.act_public_key,
                        )
                        .map_err(|e| protocol(format!("update finalization failed: {e:?}")))?;
                    self.credentials.insert(
                        act_challenge.policy_context.clone(),
                        StoredCredential {
                            token,
                            act_public_key: credential.act_public_key,
                            act_params: credential.act_params,
                        },
                    );
                }
            }
        }

        Ok(response.text().await?)
    }

    /// Send a greased presentation (a reserved 0x?A?A credential type with a
    /// random body) and return the response status. Greasing keeps Moderators
    /// honest about ignoring unknown types; callers use this to check the
    /// Moderator still answers with its ordinary challenge.
    pub async fn send_greased_presentation(&self, url: &str) -> Result<u16, ClientError> {
        let greased_type = credential_type::GREASED
            [usize::from(OsRng.next_u32() as u16) % credential_type::GREASED.len()];
        let mut body = vec![0u8; 64];
        OsRng.fill_bytes(&mut body);
        let presentation = CredentialPresentation {
            credential_type: greased_type,
            presentation_and_update: body,
        };
        let response = self
            .http
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                MoleAuthorization::Presentation(presentation.to_bytes()).to_header_value(),
            )
            .send()
            .await?;
        Ok(response.status().as_u16())
    }
}

/// Parse the Moderator's 401: the ACT credential challenge and the IHAT
/// endorsement challenge, ignoring challenges of unknown type.
fn parse_moderator_challenges(
    response: &reqwest::Response,
) -> Result<(CredentialChallenge, ModeratorChallenge), ClientError> {
    let values: Vec<&str> = response
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let challenges = parse_challenges(&values);

    let mut credential = None;
    let mut moderator = None;
    for challenge in &challenges {
        // A challenge names a single type; the Client ignores those it does
        // not recognize. The same bytes are tried under both roles, since the
        // realm does not distinguish them.
        if credential.is_none() {
            if let Ok(c) = CredentialChallenge::from_bytes(&challenge.challenge) {
                if c.credential_type == credential_type::ACT {
                    credential = Some(c);
                    continue;
                }
            }
        }
        if moderator.is_none() {
            if let Ok(m) = ModeratorChallenge::from_bytes(&challenge.challenge) {
                if m.endorsement_type == endorsement_type::IHAT {
                    moderator = Some(m);
                }
            }
        }
    }
    match (credential, moderator) {
        (Some(c), Some(m)) => Ok((c, m)),
        _ => Err(protocol(
            "moderator sent no recognizable credential + endorsement challenge pair",
        )),
    }
}

/// The scheme://host[:port] origin of a URL.
fn origin_of(url: &str) -> Result<String, ClientError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| protocol(format!("bad url: {e}")))?;
    Ok(parsed.origin().ascii_serialization())
}
