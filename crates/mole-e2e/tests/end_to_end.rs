//! End-to-end tests: boot a real Anchor and Moderator on localhost, then run
//! a Client through the full MoLE flow over HTTP — endorsement grant,
//! Redeem & Issue, Presentation and Update — plus the negative paths the
//! drafts require: double redemption, exhausted balances, replayed
//! presentations, and greased (unknown) credential types.

use std::sync::Arc;

use mole_anchor::AnchorState;
use mole_client::MoleClient;
use mole_core::config::MODERATOR_DIRECTORY_PATH;
use mole_moderator::{ModeratorConfig, ModeratorState, RESOURCE_BODY};

const EPOCH: &[u8] = b"epoch-e2e-1";
const POLICY: &[u8] = b"policy-e2e-1";

/// Everything a test needs: both servers running, their origins, and a way
/// to make clients.
struct Deployment {
    anchor_origin: String,
    resource_url: String,
    moderator: Arc<ModeratorState>,
}

/// Boot an Anchor and a Moderator (trusting that Anchor plus `extra_anchors`
/// decoys) on ephemeral ports.
async fn deploy(config: DeploymentConfig) -> Deployment {
    let anchor = Arc::new(AnchorState::new(EPOCH.to_vec(), config.grants_per_epoch));

    // The accepted set: the real Anchor plus decoys, so issuer hiding has a
    // set to hide in.
    let mut accepted = vec![
        anchor
            .public_key_bytes()
            .try_into()
            .expect("anchor keys are 33 bytes"),
    ];
    for _ in 0..config.extra_anchors {
        let decoy = AnchorState::new(EPOCH.to_vec(), 1);
        accepted.push(decoy.public_key_bytes().try_into().unwrap());
    }

    let moderator = Arc::new(
        ModeratorState::new(ModeratorConfig {
            policy_context: POLICY.to_vec(),
            accepted_anchor_keys: accepted,
            endorsement_context: EPOCH.to_vec(),
            initial_credits: config.initial_credits,
            charge: 1,
            refund: config.refund,
            act_domain_separator: b"MoLE-e2e:act:v1".to_vec(),
        })
        .expect("moderator config is valid"),
    );

    let anchor_origin = serve(mole_anchor::router(anchor.clone())).await;
    let moderator_origin = serve(mole_moderator::router(moderator.clone())).await;

    Deployment {
        anchor_origin,
        resource_url: format!("{moderator_origin}/resource"),
        moderator,
    }
}

struct DeploymentConfig {
    initial_credits: u64,
    refund: u64,
    extra_anchors: usize,
    grants_per_epoch: u32,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        DeploymentConfig {
            initial_credits: 3,
            refund: 0,
            extra_anchors: 3,
            grants_per_epoch: 8,
        }
    }
}

/// Serve a router on an ephemeral localhost port, returning its origin.
async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn full_flow_grant_redeem_present_update() {
    let deployment = deploy(DeploymentConfig::default()).await;
    let mut client = MoleClient::new(&deployment.anchor_origin, "alice");

    // First fetch: no credential, so the Client runs the grant and
    // Redeem & Issue before presenting.
    let outcome = client.fetch(&deployment.resource_url).await.unwrap();
    assert_eq!(outcome.body, RESOURCE_BODY);
    assert!(outcome.redeemed, "first fetch must run redeem & issue");
    // 3 initial credits, charge 1, refund 0: two left.
    assert_eq!(client.balance(POLICY), Some(2));

    // Later fetches present the stored (updated) credential directly.
    let outcome = client.fetch(&deployment.resource_url).await.unwrap();
    assert_eq!(outcome.body, RESOURCE_BODY);
    assert!(!outcome.redeemed, "credential must be reused, not re-issued");
    assert_eq!(client.balance(POLICY), Some(1));

    let outcome = client.fetch(&deployment.resource_url).await.unwrap();
    assert!(!outcome.redeemed);
    assert_eq!(client.balance(POLICY), Some(0));
}

#[tokio::test]
async fn refund_sustains_access() {
    // With refund == charge, presentations never exhaust the balance: the
    // Moderator is dynamically sustaining the Client's access.
    let deployment = deploy(DeploymentConfig {
        initial_credits: 1,
        refund: 1,
        ..DeploymentConfig::default()
    })
    .await;
    let mut client = MoleClient::new(&deployment.anchor_origin, "alice");

    for i in 0..5 {
        let outcome = client.fetch(&deployment.resource_url).await.unwrap();
        assert_eq!(outcome.body, RESOURCE_BODY, "fetch {i}");
        assert_eq!(client.balance(POLICY), Some(1), "fetch {i}");
    }
}

#[tokio::test]
async fn exhausted_balance_forces_new_redemption() {
    // 1 credit, no refund: the second fetch cannot present (spend proof needs
    // balance >= charge), so the Client redeems a fresh Endorsement.
    let deployment = deploy(DeploymentConfig {
        initial_credits: 1,
        refund: 0,
        ..DeploymentConfig::default()
    })
    .await;
    let mut client = MoleClient::new(&deployment.anchor_origin, "alice");

    let outcome = client.fetch(&deployment.resource_url).await.unwrap();
    assert!(outcome.redeemed);
    assert_eq!(client.balance(POLICY), Some(0));

    // The stored credential has balance 0 < charge: presentation fails
    // client-side. (The client does not yet fall back automatically; the
    // failure is the observable behavior.)
    let error = client.fetch(&deployment.resource_url).await.unwrap_err();
    assert!(
        error.to_string().contains("spend proof failed"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn independent_clients_have_independent_credentials() {
    let deployment = deploy(DeploymentConfig::default()).await;

    let mut alice = MoleClient::new(&deployment.anchor_origin, "alice");
    alice.fetch(&deployment.resource_url).await.unwrap();
    let mut bob = MoleClient::new(&deployment.anchor_origin, "bob");
    bob.fetch(&deployment.resource_url).await.unwrap();

    // Each fetch redeemed its own Endorsement and spent one presentation.
    assert_eq!(deployment.moderator.endorsement_nullifier_count(), 2);
    assert_eq!(deployment.moderator.spend_nullifier_count(), 2);
}

/// Drive the wire protocol by hand — independent of the `MoleClient`
/// plumbing — to exercise the negative paths the drafts require: replayed
/// redemptions, replayed presentations, and presentations bound to the wrong
/// challenge.
#[tokio::test]
async fn raw_replays_and_wrong_bindings_are_rejected() {
    use anonymous_credit_tokens::{Params as ActParams, PreIssuance, PublicKey as ActPublicKey};
    use ihat::anchor::AnchorPublicKey;
    use ihat::client::ClientNeedsSignature;
    use ihat::{Params as IhatParams, Proof, Signature, WireFormat};
    use mole_core::config::{AnchorDirectory, ANCHOR_DIRECTORY_PATH};
    use mole_core::http::{
        b64_decode, MoleAuthorization, MoleCredential, ENDORSEMENT_REQUEST_MEDIA_TYPE,
        MOLE_CREDENTIAL,
    };
    use mole_core::messages::{
        ActIssuanceRequest, ActIssuanceResponse, ActPresentationAndUpdate, CredentialPresentation,
        CredentialRequest, CredentialResponse, IhatGrantRequest, IhatGrantResponse,
        IhatPresentation,
    };
    use mole_core::wire::Wire;
    use mole_core::{challenge_digest, credential_type, endorsement_type};
    use rand_core::{OsRng, RngCore};

    let deployment = deploy(DeploymentConfig::default()).await;
    let http = reqwest::Client::new();
    let pp = IhatParams::standard();

    // -- Grant: the two exchanges against the Anchor. --
    let anchor_directory: AnchorDirectory = http
        .get(format!("{}{}", deployment.anchor_origin, ANCHOR_DIRECTORY_PATH))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let anchor_config = &anchor_directory.endorsement_configs[0];
    let anchor_key_bytes = b64_decode(&anchor_config.public_key).unwrap();
    let anchor_key = AnchorPublicKey::from_bytes(&anchor_key_bytes).unwrap();
    let endorse_url = format!(
        "{}{}",
        deployment.anchor_origin, anchor_config.endorse_endpoint
    );

    let grant = |step: IhatGrantRequest| {
        let http = http.clone();
        let endorse_url = endorse_url.clone();
        async move {
            let body = mole_core::messages::EndorsementRequest {
                endorsement_type: endorsement_type::IHAT,
                body: step.to_bytes(),
            };
            let bytes = http
                .post(&endorse_url)
                .header(reqwest::header::CONTENT_TYPE, ENDORSEMENT_REQUEST_MEDIA_TYPE)
                .header("x-demo-user", "mallory")
                .body(body.to_bytes())
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            let response = mole_core::messages::EndorsementResponse::from_bytes(&bytes).unwrap();
            IhatGrantResponse::from_bytes(&response.body).unwrap()
        }
    };

    let mut nf = [0u8; 32];
    OsRng.fill_bytes(&mut nf);
    let (signature_request, pending) =
        ClientNeedsSignature::request(nf.to_vec(), EPOCH.to_vec(), &mut OsRng);
    let IhatGrantResponse::Step1 {
        session_id,
        signature,
    } = grant(IhatGrantRequest::Step1 {
        signature_request: signature_request.to_bytes().unwrap(),
    })
    .await
    else {
        panic!("expected step 1 response");
    };
    let (proof_request, pending) = pending.request_proof(
        &pp,
        anchor_key,
        Signature::from_bytes(&signature).unwrap(),
    );
    let IhatGrantResponse::Step2 { proof } = grant(IhatGrantRequest::Step2 {
        session_id,
        proof_request: proof_request.to_bytes().unwrap(),
    })
    .await
    else {
        panic!("expected step 2 response");
    };
    let issued = pending
        .finalize(&pp, Proof::from_bytes(&proof).unwrap())
        .expect("honest grant finalizes");

    // -- Redeem & Issue, bound to the Moderator's endorsement challenge. --
    let moderator_challenge = deployment.moderator.moderator_challenge();
    let ihat_keys = mole_core::messages::IhatChallenge::from_bytes(&moderator_challenge.challenge)
        .unwrap()
        .keys;
    let accepted: Vec<AnchorPublicKey> = ihat_keys
        .iter()
        .map(|k| AnchorPublicKey::from_bytes(k).unwrap())
        .collect();
    let true_index = ihat_keys
        .iter()
        .position(|k| k[..] == anchor_key_bytes[..])
        .unwrap();
    let binding = challenge_digest(&moderator_challenge.to_bytes());
    let presentation = issued.show(&accepted, true_index, &binding, &mut OsRng);

    let act_params = ActParams::from_domain_separator(b"MoLE-e2e:act:v1");
    let act_public_key_bytes = {
        let directory: mole_core::config::ModeratorDirectory = http
            .get(format!(
                "{}{}",
                deployment.resource_url.trim_end_matches("/resource"),
                MODERATOR_DIRECTORY_PATH
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        b64_decode(&directory.policies[0].act_public_key).unwrap()
    };
    let act_public_key = ActPublicKey::from_bytes(&act_public_key_bytes).unwrap();

    let pre_issuance = PreIssuance::random(OsRng);
    let issuance_request = pre_issuance.request(&act_params, OsRng);
    let credential_request = CredentialRequest {
        endorsement_type: endorsement_type::IHAT,
        endorsement_presentation: IhatPresentation {
            bytes: presentation.to_bytes().unwrap(),
        }
        .to_bytes(),
        credential_type: credential_type::ACT,
        issuance_request: ActIssuanceRequest {
            truncated_key_id: mole_core::act::truncated_key_id(&act_public_key_bytes),
            request: issuance_request.to_bytes(),
        }
        .to_bytes(),
    };
    let redeem_header =
        MoleAuthorization::CredentialRequest(credential_request.to_bytes()).to_header_value();

    let first = http
        .get(&deployment.resource_url)
        .header(reqwest::header::AUTHORIZATION, &redeem_header)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 401, "issuance succeeds but still challenges");
    let credential_header = first
        .headers()
        .get(MOLE_CREDENTIAL)
        .expect("issuance returns Mole-Credential")
        .to_str()
        .unwrap()
        .to_string();

    // Replaying the identical redemption must fail: the nullifier is spent.
    let replay = http
        .get(&deployment.resource_url)
        .header(reqwest::header::AUTHORIZATION, &redeem_header)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 403, "redemption replay must be rejected");
    assert!(replay.headers().get(MOLE_CREDENTIAL).is_none());

    // -- Finalize the credential and present it. --
    let MoleCredential::Response(response_bytes) =
        MoleCredential::parse(&credential_header).unwrap()
    else {
        panic!("expected response parameter");
    };
    let credential_response = CredentialResponse::from_bytes(&response_bytes).unwrap();
    let act_response = anonymous_credit_tokens::IssuanceResponse::from_bytes(
        &ActIssuanceResponse::from_bytes(&credential_response.issuance_response)
            .unwrap()
            .response,
    )
    .unwrap();
    let ctx = mole_core::act::request_context_scalar(POLICY, EPOCH);
    let token = pre_issuance
        .to_credit_token(
            &act_params,
            &act_public_key,
            &issuance_request,
            &act_response,
            ctx,
        )
        .unwrap();

    let credential_challenge = deployment.moderator.credential_challenge();
    let (spend, _pre_refund) = token.prove_spend(&act_params, 1, 0, OsRng).unwrap();
    let good_digest = challenge_digest(&credential_challenge.to_bytes());
    let make_presentation = |digest: [u8; 32], spend_bytes: Vec<u8>| {
        MoleAuthorization::Presentation(
            CredentialPresentation {
                credential_type: credential_type::ACT,
                presentation_and_update: ActPresentationAndUpdate {
                    challenge_digest: digest,
                    key_id: mole_core::act::key_id(&act_public_key_bytes),
                    spend_proof: spend_bytes,
                }
                .to_bytes(),
            }
            .to_bytes(),
        )
        .to_header_value()
    };

    // Wrong challenge digest: understood but rejected, and crucially the
    // nullifier is NOT burned by the failed attempt...
    let wrong = http
        .get(&deployment.resource_url)
        .header(
            reqwest::header::AUTHORIZATION,
            make_presentation([0xEE; 32], spend.to_bytes()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403, "wrong challenge digest rejected");

    // ...so the correctly-bound presentation still succeeds.
    let present_header = make_presentation(good_digest, spend.to_bytes());
    let ok = http
        .get(&deployment.resource_url)
        .header(reqwest::header::AUTHORIZATION, &present_header)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.headers().get(MOLE_CREDENTIAL).is_some());

    // Replaying the identical presentation must fail: the spend nullifier is
    // recorded.
    let replay = http
        .get(&deployment.resource_url)
        .header(reqwest::header::AUTHORIZATION, &present_header)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 403, "presentation replay must be rejected");
}

#[tokio::test]
async fn greased_presentation_gets_ordinary_challenge() {
    let deployment = deploy(DeploymentConfig::default()).await;
    let client = MoleClient::new(&deployment.anchor_origin, "alice");

    // A greased (reserved, unknown) credential type with a random body must
    // be handled exactly like an unauthenticated request: a 401 with the
    // ordinary challenges, not an error.
    let status = client
        .send_greased_presentation(&deployment.resource_url)
        .await
        .unwrap();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn moderator_directory_is_served() {
    let deployment = deploy(DeploymentConfig::default()).await;
    let origin = deployment
        .resource_url
        .trim_end_matches("/resource")
        .to_string();
    let directory: mole_core::config::ModeratorDirectory =
        reqwest::get(format!("{origin}{MODERATOR_DIRECTORY_PATH}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(directory.policies.len(), 1);
    let policy = &directory.policies[0];
    assert_eq!(policy.credential_type, 1);
    assert_eq!(policy.endorsement_type, 2);
    assert_eq!(policy.accepted_anchor_keys.len(), 4);
}
